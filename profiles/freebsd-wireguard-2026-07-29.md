# Optional profile: FreeBSD wg(4) CVE-2026-58085 (2026-07-29)

Last checked: 2026-10-30. Dated snapshot. Re-read [FreeBSD-SA-26:52.if_wg](https://security.freebsd.org/advisories/FreeBSD-SA-26:52.if_wg.asc) on every run.

The 30 Oct 2026 briefing listed this item as unconfirmed. The FreeBSD Project advisory is a primary source and confirms it. `scripts/host_checks.py` still **does not** implement a FreeBSD check: that helper targets macOS, Linux and Windows only.

## What is confirmed

FreeBSD-SA-26:52.if_wg (announced 29 Jul 2026, credits Reo Shiseki):

- **CVE-2026-58085**: after a decrypt via the OpenCrypto framework, `wg(4)` did not check whether Poly1305 MAC verification succeeded, so packets with an invalid authentication tag were accepted.
- Affects all supported FreeBSD versions that ship `wg(4)`.
- Impact: a remote attacker who can send UDP to a WireGuard endpoint (and guess replay-window bounds) can inject forged or modified transport data; an on-path attacker can modify ciphertext and authenticated data without detection.
- No workaround. Systems that do not use `wg(4)` are not affected.
- Corrected 29 Jul 2026 UTC on: stable/15, 15.1-RELEASE-p2, 15.0-RELEASE-p12, stable/14, 14.4-RELEASE-p8.

## How a finding would close (on FreeBSD, collected outside this tool)

Upgrade to a supported stable/releng dated after the correction, reboot, and record the running FreeBSD version and whether `wg(4)` is loaded. This skill will not invent a host check that treats Linux/macOS WireGuard as the FreeBSD driver.

## What needs a human

Confirming the host is FreeBSD; collecting `freebsd-version` / `uname` and whether `if_wg` is in use; applying the SA.
