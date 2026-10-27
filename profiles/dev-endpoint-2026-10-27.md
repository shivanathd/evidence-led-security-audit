# Optional profile: developer-endpoint threats briefing of 2026-10-27

Last checked: 2026-10-27. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

This profile is the dated fact base for `scripts/host_checks.py`. How the checks run, what they read on each OS, and their limits are in [references/host-checks.md](../references/host-checks.md). Fleet-scale collection is in [references/endpoint-fleet.md](../references/endpoint-fleet.md). Older profiles go deeper on some of the same incidents: [litellm](litellm-2026-10-21.md), [brotli](brotli-2026-10-21.md), [emudhra](emudhra-2026-10-17.md), [php](php-2026-10-21.md), [railway](railway-2026-10-21.md) and [lightning-ai](lightning-ai-2026-10-16.md).

Versions below are the briefing's. "Unconfirmed" means the briefing marked the item unsure; those checks only list what is installed and never report it as affected.

## Check now

| Check id | Briefing fact | Source |
| --- | --- | --- |
| `testmetest-ai-hooks`, `testmetest-large-blobs`, `testmetest-npm-package` | The testmetest npm worm plants hooks for Cursor, VS Code, Claude and Gemini in GitHub repos and hides about 13 MB payloads that GitHub search misses. No package fix. Clean or rebuild the machine first, then revoke the GitHub token (it wipes the home folder if the token is revoked first). | [The Register](https://www.theregister.com/security/2026/10/26/worm-armed-42-github-repos-by-hiding-a-payload-too-big-to-fail/5305570) |
| `planted-agent-instructions`, `agent-config-endpoints`, `function-color-npm-package` | A planted `AGENTS.md` in Downloads told agents to install `function-color`; a `CLAUDE.md` redirected API traffic. Check `~/.codex/config.toml` and `.claude/settings.json` for servers or base URLs nobody added. | [The Hacker News](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html) |
| `litellm-1-107-0` | LiteLLM 1.107.0 on PyPI and Docker was malicious; pin `litellm==1.106.2`. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/), [The Hacker News](https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html) |
| `brotli-nodejs`, `brotli-python`, `brotli-dotnet` | CVE-2026-111497. Fixed in Node 22.23.4, 24.22.1 and 26.12.1; Node 20 gets no fix. Python Brotli 1.2.0 or older and brotlicffi 1.2.0.x are affected; fixed in 1.2.1 and 1.2.1.0. .NET is fixed in 8.0.33, 9.0.22 and 10.0.14. pip-audit and Dependabot do not flag it yet. | [nodejs.org](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [Aikido](https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497), [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-emergency-net-patches-for-critical-brotli-flaw/), [patchtheplanet.org](https://patchtheplanet.org/brotli) |
| `emudhra-certifi`, `emudhra-trust-store` | Update certifi to 2026.10.19 or newer. Apple blocks the eMudhra roots in Safari, Mail and apps, but curl and git on a Mac trust them until a macOS update. Trust stores are reported only, never edited. | [The Hacker News](https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html), [Unit 42](https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/), [Apple](https://support.apple.com/en-us/149555) |
| `chrome-156` | Chrome 156 fixes 353 bugs, 6 critical. | [SecurityWeek](https://www.securityweek.com/memory-bugs-account-for-most-of-chromes-353-new-security-fixes/) |
| `browser-versions` (**unconfirmed**) | Which browser CVE-2026-40369 hits, and whether it is fixed, is not confirmed. | [VoidSec](https://voidsec.com/cve-2026-40369-browser-sandbox-escape/) |

## Check if we use it

| Check id | Briefing fact | Source |
| --- | --- | --- |
| `php2shell` | PHP2Shell (CVE-2026-109618, CVE-2026-109619) fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. For CVE-2026-115560, set `session.upload_progress.enabled=0`. | [The Hacker News](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [BleepingComputer](https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/php-shares-mitigation-for-new-and-unpatched-rce-vulnerability/) |
| `railway-client` | Railway was breached 20-22 Oct; some customers' secrets were exposed. | [Railway](https://blog.railway.com/p/preliminary-report-october-security-incident) |
| `opencode-client` | Saved OpenAI, Anthropic and Google keys leaked from OpenCode Console. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/opencode-hack-exposes-api-keys-amid-ai-distillation-attacks/) |
| `warp-terminal` (**unconfirmed**) | Warp says attackers reached limited agent trace and telemetry data. | [Warp post](https://x.com/i/status/2114800787716972873) |
| `lightning-ai-client` (**unconfirmed**) | Lightning AI found stolen credentials in use on Studio. | [Lightning AI](https://lightning.ai/security-incident/) |
| `vitest-5-dev-server` | Vitest 5 dev servers could leak `.env` files, keys and `.git`; fixed in 5.0.5. | [GHSA-p458-7748-mcp3](https://github.com/advisories/GHSA-p458-7748-mcp3) |
| `pillow-13` | Pillow 13.0.0 fixes image bugs, some critical (needs Python 3.11+). | [Pillow](https://pillow.readthedocs.io/en/latest/releasenotes/13.0.0.html) |
| `ovhcloud-cli` | Versions 0.11.0 to 0.15.0 on GitHub were backdoored to steal secrets from disk; use 0.16.0. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ovhcloud-cli-releases-backdoored-on-github-to-steal-developer-secrets/) |
| `gitlab-self-hosted` | Top-score code-run bug on self-hosted GitLab. | [The Hacker News](https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html) |
| `ruby-regex` | Fixed in Ruby 4.0.9, 3.4.12 and 3.3.13; Ruby 3.2 gets no fix. | [The Hacker News](https://thehackernews.com/2026/10/ruby-fixes-three-regex-engine-bugs.html) |
| `nginx-present` | F5 fixed 3 critical NGINX bugs (no version named). | [CSO Online](https://www.csoonline.com/article/4237420/f5-rushes-out-emergency-nginx-patches-for-three-critical-flaws.html) |
| `wasmtime-embedded` | Fixed in 36.0.19, 48.0.7, 49.0.4 and 50.0.0; updating the CLI does not fix embedded copies. | [The Hacker News](https://thehackernews.com/2026/10/two-critical-wasmtime-flaws-could-let.html) |
| `qdrant-cluster` | Qdrant clusters before 1.20.0 expose an internal port with no login. | [GHSA-frc7-44gm-99qq](https://github.com/qdrant/qdrant/security/advisories/GHSA-frc7-44gm-99qq) |
| `ksmbd-linux` | Two KSMBD bugs; no kernel fix at time of writing. | [The Hacker News](https://thehackernews.com/2026/10/two-cvss-90-linux-ksmbd-rce-flaws.html) |
| `collabora-nextcloud` | CVE-2026-110447 is on the CISA exploited list. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-110447) |
| `wordpress-updraftplus` | Stolen UpdraftCentral keys are used to backdoor WordPress sites. | [The Hacker News](https://thehackernews.com/2026/10/attackers-abuse-updraftcentral-keys-to.html) |
| `magento-store` | 953 stores, mostly Magento, had hidden JavaScript in CMS blocks. | [The Hacker News](https://thehackernews.com/2026/10/hackers-infect-953-online-stores-with.html) |
| `connectwise-presence` | A hacked ConnectWise Cloud Backup app was used to hit hundreds of companies. | [The Hacker News](https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html) |

Awareness: `plex-media-server`. Four Plex bugs are on the CISA list, fixed in 1.43.3.10861. The briefing gives only the domain thehackernews.com and no URL, so this check cites no link.

## Skipped (not visible on the machine, or needs network scanning or an admin console)

| Item | Why it is skipped |
| --- | --- |
| Phishing sent through Google AppSheet | Workspace admin setting and mail-flow behaviour; nothing on the endpoint shows it |
| Microsoft 365 token replay campaign | Needs tenant sign-in logs, devices and inbox rules (admin console) |
| Fake IT support in external Teams chats | Tenant setting (external access); not visible on the endpoint |
| Unbounce connected-app keys | SaaS account; no local client or artifact named in the briefing |
| Bullhorn platform offline | SaaS platform; no local artifact |
| iPhone jailbreak on iOS 27.1 | Mobile devices; needs MDM inventory, not a laptop scan |
| Arista VeloCloud Orchestrator | Network appliance; needs the admin console or network scanning |
| Palo Alto PAN-OS / Prisma Access | Firewall appliance; needs the admin console |
| Fortinet FortiOS / FortiProxy / FortiPAM | Network appliance; needs the admin console |
| Hostwinds client area offline | Hosting account; no local artifact |
| PingCAP / TiDB Cloud data copied | Cloud service account; no local artifact named in the briefing |
| Magento `cms_block` content | Needs database access; `magento-store` only finds Magento code on disk |
| Salesforce outage and other awareness-only items | The briefing says no action |
| Bun and Envoy/Istio Brotli reports | Marked unconfirmed in the briefing with no versions |

## How this maps to the skill

- Target: one `other` target per machine (the locator is a device id, never a hostname in a public report). Run with `--target ID` and merge `report_fragments` into the report. NOT_APPLICABLE checks still need a human `approved_by_role`.
- A `testmetest` or LiteLLM hit is also a credential-exposure event (phase 4): list every credential the machine could read.
- A version check that passes on this machine says nothing about Docker images or servers built elsewhere. Image tags found on disk are listed, but the images themselves are not opened.

## What needs a human

Deciding whether a hook, blob or instruction file was added by the owner; rebuilding machines; revoking tokens in the order above; editing trust stores; and approving NOT_APPLICABLE checks.
