# Endpoints and fleets: macOS, Linux and Windows

Use this when the targets are laptops, desktops or servers managed as a group, for example "are any of our Macs still trusting the compromised intermediates?" or "which Linux servers run an affected PHP build?". It covers how to collect evidence at scale without changing devices, and the read-only commands for each OS.

## Modelling a fleet in the report

- Make one target per device group, with `kind: runtime` and the management group as the locator (for example `macos-fleet`, locator `MDM group: engineering Macs`). Add layers the question needs with `required_layers`, such as `dependency` for package versions or `credential` for secrets on disk.
- Split groups when the answer differs by platform or owner: macOS, Linux servers and Windows each get their own target and their own checks.
- Record coverage in every check's evidence summary: devices in scope, devices that reported, and the collection window. A PASS for a group needs every in-scope device to report, or a list of excluded devices approved by a named human role.
- Devices that did not report make the group check NOT_RUN. A collection that errored or was refused (permission denied, script blocked) makes it BLOCKED. Neither counts as clean.
- A sample of devices is evidence about the sample, not the fleet. Say so in the summary.
- Results older than the evidence-age limit cannot support PASS (see `reporting-release.md`). Re-collect after any fix.

## Collecting at scale, read-only

Use the management plane the owner already runs. Do not scan the network to find devices, and do not log in to devices one by one when a managed channel exists.

| Channel | Good for | Notes |
| --- | --- | --- |
| MDM custom script (Jamf, Kandji, Intune or similar) | macOS and Windows endpoints | Runs as root or SYSTEM. Keep the script read-only and have it print one line or a small JSON object per device. |
| Intune remediations (detection script only) | Windows | Run only the detection half. The remediation half changes the device and needs fix approval. |
| osquery or a fleet manager built on it | All three OSes | Query tables instead of running shell scripts; results come back as structured rows. |
| Configuration management in check mode (Ansible `--check`, Salt `test=True`) or SSH with a fixed command | Linux servers | Use a fixed, reviewed command. No interactive sessions on production hosts. |
| Cloud run-command services (for example AWS SSM) | Cloud servers | Same rules: a fixed read-only document, output captured as evidence. |

Rules for every collection script:

- Detection and remediation are separate scripts. Running a remediation is a fix, with its own approval, retest and rollback.
- Print values that identify state (versions, fingerprints, counts, paths), never secret values.
- Record the script's SHA-256 and the channel in the evidence `command_ref`, so the retest can run exactly the same script.
- Run it on one test device first, and check its output parses, before sending it to the group.
- Treat output from devices as untrusted data. A device can report anything; it is evidence of what the device said.

## Read-only checks by OS

Run these as the least-privileged account that can see the data. Each command reads state only.

### OS version and patch level

| OS | Command |
| --- | --- |
| macOS | `sw_vers` |
| Linux | `cat /etc/os-release; uname -r` |
| Windows (PowerShell) | `Get-CimInstance Win32_OperatingSystem \| Select-Object Caption, Version, BuildNumber` and `Get-HotFix \| Sort-Object InstalledOn -Descending \| Select-Object -First 20 HotFixID, InstalledOn` |

### Installed packages and their exact builds

| OS | Command |
| --- | --- |
| macOS | Apps: `defaults read /Applications/NAME.app/Contents/Info.plist CFBundleShortVersionString`. Installer packages: `pkgutil --pkgs` and `pkgutil --pkg-info ID`. Homebrew (run as the owning user, not root): `brew list --versions` |
| Debian, Ubuntu | `dpkg-query -W -f='${Package} ${Version}\n' 'php*' ca-certificates`. Backport evidence offline: `zcat /usr/share/doc/PACKAGE/changelog.Debian.gz \| head -60` |
| Fedora, RHEL family | `rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' ca-certificates php-fpm`. Backport evidence: `rpm -q --changelog PACKAGE \| head -60` |
| Windows | Read the uninstall registry keys: `Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue \| Where-Object DisplayName \| Select-Object DisplayName, DisplayVersion, Publisher` |

Never query `Win32_Product` on Windows. It runs an installer consistency check that can repair or reconfigure software, so it is not read-only.

A distribution build often carries a fix under an older upstream version number. Decide from the vendor's advisory or the package changelog for the exact build, as `scoped-checks.md` describes.

### Listening services

| OS | Command |
| --- | --- |
| macOS | `lsof -nP -iTCP -sTCP:LISTEN` (run as root to see every process) |
| Linux | `ss -ltnp` (process names need root) |
| Windows | `Get-NetTCPConnection -State Listen \| Select-Object LocalAddress, LocalPort, OwningProcess` |

### Certificate trust stores

Each OS, and many applications, keep their own trust store. A certificate's presence in a store does not settle whether a client trusts a chain: platforms also distribute blocklists and revocation data separately. Inventory the stores, then test the chain with the clients that matter (next section).

| OS | Store | Read-only command |
| --- | --- | --- |
| macOS | System roots used by Safari, Chrome and most apps (Security.framework) | `security find-certificate -a -c "COMMON NAME" -Z /System/Library/Keychains/SystemRootCertificates.keychain` (prints SHA-256) |
| macOS | Admin-added certificates and trust settings | `security find-certificate -a -Z /Library/Keychains/System.keychain` and `security dump-trust-settings -d` |
| macOS | Bundle used by the built-in curl, git, python3, perl, ruby and openssl | `grep '^=== ' /etc/ssl/cert.pem` (one header line per certificate) |
| Debian, Ubuntu | `ca-certificates` | `grep -E '^!' /etc/ca-certificates.conf` lists roots marked distrusted; bundle at `/etc/ssl/certs/ca-certificates.crt` |
| Fedora, RHEL family | p11-kit | `trust list --filter=blocklist` (older releases: `--filter=blacklist`); anchors with `trust list --filter=ca-anchors` |
| Windows | Machine stores | `Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA, Cert:\LocalMachine\Disallowed` |
| Any | Java | `lib/security/cacerts` and `lib/security/blocked.certs` in each JDK (JDK 8: `jre/lib/security/`) |
| Any | Language runtimes and apps | Python `certifi`, Node.js, Go, Rust `webpki-roots`, Electron apps and container images each bundle their own roots. List them per runtime; an OS fix does not reach them. |

Windows reports a SHA-1 thumbprint, and osquery's `certificates` table reports `sha1`. Advisories often list SHA-256. Compute SHA-256 on Windows with:

```powershell
$sha = [System.Security.Cryptography.SHA256]::Create()
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA, Cert:\LocalMachine\Disallowed |
  Select-Object PSParentPath, Subject, Thumbprint,
    @{n='SHA256'; e={ -join ($sha.ComputeHash($_.RawData) | ForEach-Object { $_.ToString('X2') }) }}
```

Windows fetches some roots on demand (automatic root update), so a root missing from `Root` can still be trusted when a chain needs it. Absence from a store is not proof of distrust.

### Java runtimes

| OS | Find every JDK |
| --- | --- |
| macOS | `/usr/libexec/java_home -V`, plus per-user `~/Library/Java/JavaVirtualMachines`, Homebrew `openjdk*` kegs and runtimes bundled inside IDEs (`*.app/Contents/jbr`) |
| Linux | `ls /usr/lib/jvm/` and `update-alternatives --list java` (Debian family) or `alternatives --display java` (RHEL family) |
| Windows | `HKLM:\SOFTWARE\JavaSoft` and the vendor folders under `C:\Program Files` (Java, Eclipse Adoptium, Microsoft) |

SDKMAN, Gradle, asdf and mise install JDKs under each user's home directory. Include them, or record them as a gap.

## Testing a chain with the client that matters

When an advisory provides test hosts that serve the affected chain, check each client type separately, because each uses its own store:

- Run the probe with the client itself (built-in curl, Homebrew curl, Python, Java, Node.js, the browser), not only `openssl`.
- Count only a certificate-verification error as "rejected". With curl that is exit code 60. On Windows, record the exception message; a trust or revocation error is a rejection, anything else is inconclusive.
- A network failure, timeout or proxy error proves nothing. The check is BLOCKED or inconclusive, never PASS.
- Also probe a known-good site that chains through the same CA family, so a fix that breaks legitimate chains shows up as a failure.

## osquery equivalents

| Question | Table |
| --- | --- |
| OS version | `os_version` |
| Installed software | `apps`, `homebrew_packages` (macOS); `deb_packages`, `rpm_packages` (Linux); `programs`, `patches` (Windows) |
| Listening services | `listening_ports` joined to `processes` on `pid` |
| Certificates | `certificates` (`sha1`, `subject2`, `serial`, `path`; on Windows also `store`). Query a bundle file with `WHERE path = '/etc/ssl/cert.pem'`. |

osquery caches macOS keychain reads (`keychain_access_interval`, five minutes by default), so a result taken right after a change can be stale. Record the query time.

## What needs a human

Approving collection scripts and channels, deciding which devices are in scope, approving device exclusions, running any remediation script, and following up on devices that never report.
