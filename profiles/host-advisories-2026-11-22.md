# Optional profile: host advisories 2026-11-22 (Bitwarden CLI CVE-2026-42994)

Last checked: 2026-11-22. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `bitwarden-cli-42994`. Read-only metadata and leftover-file names/hashes only. Never start `bw`, bun or `gh`, never contact npm or GitHub, never store an exfil URL or IP, and never run install scripts.

Already on main (do not re-implement): dated 20 Nov checks (`openssl-121481`, `gpustack-102895`, `vmware-tools-123894`, `asus-acce-114202`).

## Terms

- **Malicious version**: npm `@bitwarden/cli` **exactly 2026.4.0**. Bitwarden and community notes say there was never a valid vendor 2026.4.0 release. The version object is unpublished; npm still has `time["2026.4.0"]` = `2026-04-22T21:22:59.021Z`.
- **Vendor floor**: **2026.4.1** (published `2026-04-23T15:54:37.374Z`; `bin.bw` = `build/bw.js`). Later 2026.x releases exist; latest observed while writing this profile: **2026.11.0**.
- **Last clean before the incident**: **2026.3.0** (`2026-04-02T17:27:31.694Z`).
- **Vendor/CVE window**: npm installs of 2026.4.0 between **2026-04-22T21:57Z and 2026-04-22T23:30Z** (5:57 PM–7:30 PM ET / 3:27–5:00 AM IST on 23 Apr 2026). npm's published time is about 35 minutes earlier; record both, do not invent a single timestamp.
- **GHSA-g98r patched versions "None"**: malware-advisory style. Do not treat that as "no fix". Bitwarden tells users to install 2026.4.1.

## Primary sources

- Bitwarden community statement: [Checkmarx supply-chain incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- NVD: [CVE-2026-42994](https://nvd.nist.gov/vuln/detail/CVE-2026-42994)
- GitHub: [GHSA-999x-2wm3-jfx8](https://github.com/advisories/GHSA-999x-2wm3-jfx8) (CVE) and [GHSA-g98r-qjhg-4fmr](https://github.com/advisories/GHSA-g98r-qjhg-4fmr) (malware advisory)
- Tracking issue: [bitwarden/clients#20353](https://github.com/bitwarden/clients/issues/20353)
- JFrog: [Bitwarden CLI hijack](https://research.jfrog.com/post/bitwarden-cli-hijack/)
- StepSecurity: [Bitwarden CLI hijacked on npm](https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools)
- OX Security: [Shai-Hulud Bitwarden CLI](https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/)
- Socket: [Bitwarden CLI compromised](https://socket.dev/blog/bitwarden-cli-compromised)
- Ossprey: [Bitwarden CLI supply-chain attack](https://www.ossprey.com/blog/bitwarden-cli-supply-chain-attack)

An unverified YouTube Short (Better Stack, `06m-t-LwsDA`) was a lead only. The confirmed incident is April 2026; do not trust "just caught" framing.

## What was disclosed (as of the date above)

**npm `@bitwarden/cli` 2026.4.0.** A malicious package was on the npm registry for a short window on 22 Apr 2026 and was later unpublished. The loader `bw_setup.js` (preinstall `node bw_setup.js`, `bin.bw` redirected to the loader) downloaded Bun 1.3.13 from `github.com/oven-sh/bun` if needed and ran `bw1.js`. Embedded app metadata still referenced 2026.3.0.

**Published SHA-256 (JFrog / StepSecurity).** Loader `bw_setup.js` `18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb`; payload `bw1.js` `8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14`; tampered root metadata `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad`.

**Collection.** Filesystem and env/shell collectors for GitHub and npm tokens, SSH keys, AWS / GCP / Azure creds, shell history, GitHub Actions secrets, and AI / MCP / cloud tooling config. JFrog describes a GitHub Actions runner collector. Ossprey / Socket describe a memory-scraping script aimed at the Actions `Runner.Worker` process on Linux `GITHUB_ACTIONS`. That last behaviour is confirmed as described in those write-ups; this helper does not scrape process memory.

**Exfil (not stored here).** Primary HTTPS endpoint reported by researchers; fallback public GitHub repos under the victim account with Dune-themed `{word}-{word}-{3digits}` names and description `Shai-Hulud: The Third Coming`. Debug string: `Would be executing butlerian jihad!`.

**Kill switch (context only).** OX: `bw1.js` exits 0 if a Russian locale is seen (`Intl`, then `LC_*` / `LANG`, then Windows env when `SystemRoot` is set; match on `ru`). Not implemented as a check.

**Persistence / leftover files.** Injection into `~/.bashrc` and `~/.zshrc`; lock file `/tmp/tmp.987654321.lock`; staging `/tmp/_tmp_` and `package-updated.tgz`. Ossprey describes at least one rc injection as `echo << 'EOF'` (a no-op that poisons AI context).

**Official impact.** Bitwarden reports no evidence that end-user vault data or production systems were compromised. Snap package not affected. npm path only.

**Unconfirmed CI vector.** The Short claimed a compromised GitHub Action inside Bitwarden's own CI. Bitwarden attributes the npm delivery path to a broader Checkmarx incident and says compromised access was revoked. Researcher write-ups (JFrog, Socket, OX, issue #20353) discuss GitHub Action / publish-workflow abuse, sometimes naming `checkmarx/ast-github-action` or a stolen token. Record the conflict; do not encode an unconfirmed CI vector as a host check.

TTPs overlap Shai-Hulud / "Third Coming" / TeamPCP. That is attribution context, not a second product to check.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| npm `@bitwarden/cli` | 2026.4.1 (exactly 2026.4.0 is the malicious version) | Bitwarden community / GHSA-999x / npm 2026.4.1 `bin.bw` |

## What this helper checks

- Lockfiles and `package.json` for `@bitwarden/cli`: exact **2026.4.0** is `affected`; exact **2026.4.1+** is `info`; ranges that can resolve to 2026.4.0 (`^2026.3.0`, `*`, `latest`) are `review`; `~2026.3.0` cannot include 2026.4.0 and is `info`.
- Scoped install path `node_modules/@bitwarden/cli` (`os.path.join(nm, "@bitwarden", "cli")`), global npm / nvm / fnm / volta / bun / pnpm prefixes, `.package-lock.json`, pnpm virtual store `@bitwarden+cli@` plus version 2026.4.0.
- npm cache index needle `/@bitwarden/cli/-/cli-2026.4.0` (not `@bitwarden/cli-2026.4.0.tgz`).
- Leftover `bw_setup.js` / `bw1.js` under walked roots, the scoped install dir, and temp dirs: matching published SHA-256 is `affected`; name-only is `review`; unreadable is `unknown`.
- Published leftover names: `tmp.987654321.lock`, `package-updated.tgz`, directory `_tmp_`.
- `~/.bashrc` and `~/.zshrc` unique needles only (loader/payload names, butlerian-jihad string, `Shai-Hulud: The Third Coming`, `echo << 'EOF'`). Ordinary "bitwarden" or lone Dune-word mentions are not findings. No Windows rc named in the write-ups.
- Cheap git hint: indexed repo directory names, remotes, or `.git/description` matching the published Dune `{word}-{word}-{3digits}` pattern or the exact description string. `review` only. No GitHub API.

## Out of scope (not a host check)

- Unconfirmed Bitwarden-own GitHub Action CI claim / `checkmarx/ast-github-action` as a local check.
- Snap, Homebrew, Chocolatey, or other non-npm Bitwarden CLI channels.
- Exfil URL or IP (no network; not stored).
- Locale kill switch (would execute payload logic).
- `Runner.Worker` process-memory scrape.
- Treating GHSA-g98r patched versions `None` as "no vendor fix".
- Starting `bw`, bun or `gh`; npm registry or GitHub API calls; install hooks.
