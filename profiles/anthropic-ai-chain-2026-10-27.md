# Optional profile: Anthropic AI-discovered exploit chains of 2026-10-27

Last checked: 2026-10-28. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

The durable check class is **browser and OS patch level** on an endpoint. `scripts/host_checks.py` check id: `anthropic-ai-chain` (confirmation: **unconfirmed** for mapping a given host to these chains).

## Primary sources

- Anthropic research post (2026-10-27): [Discovering and exploiting vulnerabilities in critical, real-world software with Claude](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude)
- Chrome floor named in that post: patched **as of Chrome 156** (62 CVEs assigned, the post says)
- Windows: the post names **CVE-2026-33096** (HTTP/3 QUIC). Confirm against a Microsoft advisory before treating a build as fixed
- Linux: the post names **CVE-2026-98432** (MPTCP UAF). Confirm against the kernel stable-tree commit or the distro advisory before treating a kernel as fixed
- Safari / Android: the post says the vendors implemented a fix. **No desktop Safari or Android build number** was retrieved on this run

News coverage that describes "one exploit chain across Chrome, Safari, Windows, Linux and Android" is a summary. The primary post describes **five separate attack chains**, one per platform.

## What was disclosed (as of the date above)

Verified from the Anthropic post:

- Anthropic used an unreleased internal model to find and exploit vulnerabilities in widely used software and reported them under coordinated disclosure.
- Five chains: Chrome one-click RCE; Safari SOP bypass; Android lock-screen bypass; Windows remote HTTP/3 DoS (CVE-2026-33096); Linux zero-click RCE (CVE-2026-98432).
- Chrome: "62 CVEs have been assigned and patched as of Chrome 156".
- Safari and Android: "a fix is available" / "addressed by Google" — **exact builds unverified**.
- Windows and Linux CVE ids are named in the post; **exact patched OS builds unverified** against a vendor bulletin retrieved for this check.

Unverified, and labelled as such in the check and the report:

- That a given host is vulnerable to, or patched against, those chains (except the dated Chrome 156 floor)
- Desktop Safari / macOS version that closes the SOP chain
- Distro kernel package that contains the CVE-2026-98432 backport
- Windows build that contains CVE-2026-33096
- Any claim that the five chains are a single cross-platform exploit

## How this maps to the skill

This is a **runtime** endpoint check. `host_checks.py` never fetches "current stable" (no network). It compares Chrome/Chromium to the dated 156 floor and records other browser and OS versions as info with an unverified note. When any component is present the check is **BLOCKED** with the unconfirmed host-mapping reason, even if Chrome is current. That is intentional: a current Chrome does not prove Safari, Windows or Linux are patched for the other chains.

- Chrome / Chromium below 156 → `review`
- Chrome 156 or newer → `info` (dated floor only)
- Safari, other browsers, kernel, Windows build → `info`, detail says **unverified**
- Nothing installed and no kernel/OS record → `NOT_APPLICABLE`

Do not write or run an exploit. Do not treat this check as proof the chain exists on a given build.

## Closing a finding under this profile

There is no automatic `vendor_patch` close from this check alone.

- Chrome: `vendor_patch` only with a vendor advisory retrieved this run that still names 156 (or a later floor) and evidence that build is running
- Safari / Windows / Linux / Android: `BLOCKED` / UNKNOWN until a primary vendor bulletin names the exact build and that build is observed
- The check confirmation stays **unconfirmed** for host mapping even after Chrome is updated

## Report wording

- Check title: `Browser and OS patch level (Anthropic AI-discovered chain, unconfirmed)`.
- Finding summary: name the browser or OS, the recorded version, and whether the floor is dated or unverified. Never say "affected by the Anthropic chain" for Safari, Windows, Linux or Android.
- Verdict: unchanged.

## What needs a human

Refreshing vendor bulletins for Safari, Windows, Linux and Android, and deciding whether the dated Chrome floor is still the right comparison.
