# Optional profile: Go MPTCP default and Linux kernel CVE-2026-98432 (2026-10-29)

Last checked: 2026-10-30. Dated snapshot. Re-read [golang-announce](https://groups.google.com/g/golang-announce/c/PCoQcdxoScw) on every run.

## What is confirmed

The Go Security Team (Neal Patel, 29 Oct 2026) wrote:

- **CVE-2026-98432** is a use-after-free in Linux kernel IPv4 TCP connection handling.
- A demonstrated exploit (described by Anthropic) used a server with Multipath TCP (MPTCP) listeners for remote code execution.
- The underlying kernel bug is **not** specific to MPTCP. Hosts with no MPTCP listener may still be vulnerable to similar attacks.
- As of **Go 1.24**, Go programs enable MPTCP by default for listen sockets on Linux.
- Mitigation in Go (fragile): `GODEBUG=multipathtcp=0` at runtime, or `godebug multipathtcp=0` in the main module's `go.mod`. `net.Dialer.SetMultipathTCP` / `net.ListenConfig.SetMultipathTCP` override the GODEBUG setting.
- The recommended fix is a **patched kernel**. The announce names **no** patched kernel version and says it is premature to change Go's default.

## What this skill will not invent

No Linux distro package name, no kernel ABI, and no "fixed in 6.x.y" string appears here. A `go-mptcp-linux` finding of `review` means: Go 1.24+ is present on Linux without the named GODEBUG mitigation. It is not proof the running kernel is vulnerable or patched.

## How a finding closes

Closing needs a distro or vendor kernel advisory retrieved this run, plus evidence the **running** kernel is that build. A `godebug` line in `go.mod` is mitigation, not a kernel fix.

## What needs a human

Matching `/proc/version` (or the equivalent) to a distro advisory; deciding whether every Go service on the host is rebuilt with the mitigation; accepting residual kernel risk.
