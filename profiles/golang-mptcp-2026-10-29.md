# Optional profile: Go MPTCP default and Linux kernel CVE-2026-98432 (2026-10-29)

Last checked: 2026-11-03. Dated snapshot. Re-read [golang-announce](https://groups.google.com/g/golang-announce/c/PCoQcdxoScw), [Ubuntu CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432), the [Ubuntu proposed-pocket note](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432) (2 Nov 2026), [RHSA-2026:93412](https://access.redhat.com/errata/RHSA-2026:93412) / [93413](https://access.redhat.com/errata/RHSA-2026:93413) / [93414](https://access.redhat.com/errata/RHSA-2026:93414), and the [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-98432) on every run.

## What is confirmed

The Go Security Team (Neal Patel, 29 Oct 2026) wrote:

- **CVE-2026-98432** is a use-after-free in Linux kernel IPv4 TCP connection handling.
- A demonstrated exploit (described by Anthropic) used a server with Multipath TCP (MPTCP) listeners for remote code execution.
- The underlying kernel bug is **not** specific to MPTCP. Hosts with no MPTCP listener may still be vulnerable to similar attacks.
- As of **Go 1.24**, Go programs enable MPTCP by default for listen sockets on Linux.
- Mitigation in Go (fragile): `GODEBUG=multipathtcp=0` at runtime, or `godebug multipathtcp=0` in the main module's `go.mod`. `net.Dialer.SetMultipathTCP` / `net.ListenConfig.SetMultipathTCP` override the GODEBUG setting.
- The recommended fix is a **patched kernel**. The announce names **no** patched kernel version and says it is premature to change Go's default.
- Ubuntu fixes in -proposed (2 Nov 2026); RHEL fixed via RHSA-2026:93412/93413/93414 (1 Nov 2026). Those Ubuntu ABIs are not in `-updates` or `-security`. Ubuntu 26.10 stays review (blog vs CVE page).
- CVE record published 15 Oct 2026, updated 30 Oct 2026 lists upstream floors 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10 (7.3+ unaffected; introduced in 4.4). Those are not distro package floors.

## What this skill will not invent

No Linux distro package name, no kernel ABI, and no "fixed in 6.x.y" string appears in the Go check. A `go-mptcp-linux` `review` on a `go.mod` file means Go 1.24+ is present without the named GODEBUG mitigation. A `review` on a Linux Go toolchain or `golang-go` package means the GODEBUG mitigation was not verified for that install (a mitigated `go.mod` can still sit next to an unmitigated toolchain). None of those findings prove the running kernel is vulnerable or patched. The running-kernel record is `linux-tcp-uaf-98432`. Ubuntu at or above a proposed ABI is review, not a released fix. Do not PASS an Ubuntu ABI against the cve.org upstream floors.

## How a finding closes

Closing needs a distro or vendor kernel advisory retrieved this run that names a **released** fixed build, plus evidence the **running** kernel is that build. A `godebug` line in `go.mod` is mitigation, not a kernel fix. Ubuntu `-proposed` ABIs and WIP targets are not that evidence.

## What needs a human

Matching `/proc/version` (or the equivalent) to a distro advisory; deciding whether every Go service on the host is rebuilt with the mitigation; accepting residual kernel risk.
