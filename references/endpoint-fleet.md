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
| Debian, Ubuntu | Pattern query: `dpkg-query -W -f='${Package} ${Version}\n' 'php*' 'php8*' php-fpm ca-certificates 'libbrotli*' brotli 'nodejs*' 'node-*' bun 'nginx*' 'envoy*'`. `dpkg-query -W` with several patterns exits 1 if any one pattern is missing, even when others hit. Query one pattern at a time, or ignore the exit code and parse stdout. An empty result for a pattern is `NOT_APPLICABLE` for that name; keep the command output. Backport evidence offline: `zcat /usr/share/doc/PACKAGE/changelog.Debian.gz \| head -60` |
| Fedora, RHEL family | Pattern query: `rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'brotli*' 'libbrotli*' 'nodejs*' bun 'nginx*' 'envoy*' ca-certificates php-fpm 'php*' 'php8*'` or `dnf list --installed 'brotli*' 'libbrotli*' 'nodejs*' bun 'nginx*' 'envoy*' php-fpm 'php*'`. Prefer `-qa` / glob forms; `rpm -q exact-name` on a missing name is a gap, not a PASS. Backport evidence: `rpm -q --changelog PACKAGE \| head -60` |
| Alpine | `apk info -e brotli brotli-libs nodejs bun nginx envoy ca-certificates php82 php83 php84 php83-fpm php-fpm` prints only installed names. Then `apk policy PKG` for the version. A name `-e` omits is `NOT_APPLICABLE` with that output. There is no `libbrotli` package; the shared libraries are `brotli-libs`. |
| Arch and derivatives | Local pattern query: `pacman -Qs 'brotli|nodejs|bun|nginx|envoy|ca-certificates'`. A name with no hit is `NOT_APPLICABLE`. |
| openSUSE | `rpm -qa` patterns as on Fedora, or `zypper se -i brotli nodejs bun nginx envoy` |
| Windows | Read the uninstall registry keys: `Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue \| Where-Object DisplayName \| Select-Object DisplayName, DisplayVersion, Publisher`. Package managers (read-only): `winget list`. Chocolatey 2+: `choco list` is local-only; do not pass a source. Chocolatey 1.x needs `--local-only`. Never use `winget upgrade` or `choco upgrade` during an audit. |

Never query `Win32_Product` on Windows. It runs an installer consistency check that can repair or reconfigure software, so it is not read-only.

A distribution build often carries a fix under an older upstream version number. Decide from the vendor's advisory or the package changelog for the exact build, as `scoped-checks.md` describes.

### Bundled native libraries

Use this when an advisory is in a library that runtimes **bundle** (compression, image codecs, TLS). A lockfile or scanner miss is common. Record every copy: system package, language wheel, runtime binary, container layer, vendored tree. Commands read state only. Do not feed crafted files to a decoder.

Default: do **not** start Node, Bun, Python, pip, poetry, uv, curl, PHP, or a mesh CLI to "check" a suspect install. Those load site customizers, `.pth` files or the binary itself. That is the LiteLLM-class trigger this skill forbids. Exceptions: `istioctl version --remote=false` in the Envoy / Istio row is a local-CLI read that does not contact the mesh; the Tailscale / overlay commands in [Mesh VPN SSH and privileged forwarding](#mesh-vpn-ssh-and-privileged-forwarding) are local status reads and must not `ping` or `ssh` a peer. Cert-chain live probes in [Testing a chain with the client that matters](#testing-a-chain-with-the-client-that-matters) start a named client; they must not start a path inventory flagged as a suspect hijacked install. Read lockfiles, `*.dist-info/METADATA`, the package database, and linked-library metadata on a **named** binary path.

| Where | macOS | Linux | Windows (PowerShell) | Containers |
| --- | --- | --- | --- | --- |
| Node.js | Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` / `bun.lockb`). Package DB / `brew list --versions node`. Linked libs on a named path: `otool -L /usr/local/bin/node` (path from the package DB). Do not run `node`. | Same; `readelf -d /usr/bin/node` or `objdump -p /usr/bin/node` (look for `NEEDED`). | Same lockfile and package-DB read. `dumpbin /dependents` on a named `node.exe` only if that tool is already installed. | Package DB and the named binary **inside** the image digest |
| Bun | Lockfiles; `brew list --versions bun`; `otool -L` on the named `bun` binary | `readelf -d` / `objdump -p` on the named `bun` binary | `dumpbin /dependents` on the named `bun.exe` | Same inside the image |
| Python wheels | Read `*.dist-info/METADATA` and lockfiles (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt`). Do not run `python`, `pip`, `uv` or `poetry`. | Same | Same under `%LOCALAPPDATA%` and project `.venv` | Read site-packages in the image filesystem |
| System Brotli | Homebrew: `brew list --versions brotli` | Distro pattern queries above (`libbrotli*` / `brotli` / Alpine `brotli-libs`) | `winget list brotli` if a package is registered | Package database **in the image digest** |
| curl / libcurl | `otool -L /usr/bin/curl` on that named path. A curl version string does not prove the linked libbrotli build. Do not run `curl --version`. | `readelf -d /usr/bin/curl` or `objdump -p /usr/bin/curl`. Do not use `ldd` (it loads the binary). | `dumpbin /dependents` on a named `curl.exe` | Same inside the image |
| Envoy / Istio | File metadata of the named `envoy` binary. Local CLI only: `istioctl version --remote=false`. Mesh / control-plane version is a **separate** owner-approved cluster read, not this command. | Same | Unusual on Windows; record as a gap if the fleet has none | Image tag **and** digest; effective EnvoyFilter / decompressor config from the spec |
| Vendored C copies | Search `vendor/`, `third_party/` and similar for a `brotli` tree; record the path and any VERSION / CMake file. Inventory skips `node_modules` and `.venv` by default. | Same | Same under the project tree | Same inside the image |
| Image parsers | Same lockfile / `METADATA` read for Pillow | Same | Same | Same |

Rules:

- A CLI on the audit laptop is not evidence for a server or an image.
- A package or wheel version is evidence for that layer only.
- If a live query is unavoidable, use an **already-running** owner worker. Confirm the on-disk binary (`/proc/<pid>/exe` or the owner's equivalent) is not a path inventory flagged as a suspect install. Do not start a new interpreter to collect the version.
- If the advisory names a config switch (Brotli decompressor on, a test-runner `--ui` flag), record the effective setting as well as the version.
- SBOMs (`bom.json`, `*.cdx.json`, `*.spdx.json`) are leads. Confirm each listed component against a lockfile or the image.

### Known-bad package versions

Compare inventoried versions with hijack records refreshed this run. Do not install or import the package to test it.

| OS | Read-only commands |
| --- | --- |
| Any project tree | Read lockfiles and SBOMs that `scripts/inventory.py` listed: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` / `bun.lockb`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt`. Compare the exact version or digest with records refreshed this run. Do not run `npm` / `pnpm` / `yarn` / `bun` / `pip` / `uv` / `poetry` install commands. |
| macOS / Linux | Search package metadata for a directory named after the bad version (for example `PACKAGE-1.2.3.dist-info` or `node_modules/PACKAGE/package.json`). Do not start the language runtime in that tree if the advisory says install or startup hooks run. |
| Windows | The same metadata search under `%LOCALAPPDATA%\Programs`, `%APPDATA%\npm` and project `.venv` / `node_modules` folders. |
| Images | `docker image inspect IMAGE@DIGEST` (or the owner's equivalent) for tags and the digest. Match the digest the advisory published. |
| System packages | Same `dpkg-query` / `rpm` / `dnf` / `apk` / `pacman` / `brew` / `winget` commands as the installed-packages table, then compare the build with the hijack record. |

### Dev and debug servers

| OS | Read-only commands |
| --- | --- |
| Any | Lockfile version of the test runner or bundler. Config flags: `--ui`, Browser Mode, `api`, `server.host`. |
| macOS | `lsof -nP -iTCP -sTCP:LISTEN` |
| Linux | `ss -ltnp` |
| Windows | `Get-NetTCPConnection -State Listen` |

Do not request `/.env` or other secret files from the listener. Version plus bind evidence is enough.

### PHP serving-runtime versions

Use this when inventory listed `php_runtime_hints` or the engagement is the October 2026 PHP RCEs. Do not start `php` or `php-fpm` to collect a version.

| Where | Read-only evidence |
| --- | --- |
| Project tree | `composer.json` `require.php` / `require-dev.php` / `config.platform.php`; `composer.lock` `platform.php` / `platform-overrides.php`. These are constraints, not runtime proof. |
| Debian, Ubuntu | `dpkg-query -W -f='${Package} ${Version}\n' 'php8*' php-fpm 'libapache2-mod-php*'` one pattern at a time. |
| Fedora, RHEL family | `rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*' php-fpm` |
| Alpine | `apk info -e php82 php83 php84 php83-fpm php-fpm` then `apk policy PKG` |
| macOS | Homebrew: `brew list --versions php`. App bundle version from `Info.plist` if a named PHP application bundle exists. |
| Windows | `winget list php` if registered. Do not start `php.exe`. |
| Image | Labels and the package DB **inside** the digest. Official `php:` / `php-fpm` tags are hints. |
| Already-running worker | Owner-run read of that process only, after confirming `/proc/<pid>/exe` (or the owner's equivalent) is not a suspect install. Do not start a new SAPI. |

`phpmyadmin` and other application names that start with `php` are not a PHP runtime.

### Mesh VPN SSH and privileged forwarding

Use this when inventory listed `mesh_vpn_hints` or the host may run Tailscale, Headscale, ZeroTier or NetBird. Every command below is local and read-only. Do not `tailscale set`, `up`, `ssh`, `ping`, `serve` or otherwise contact another node. Do not enable or disable SSH.

Record booleans, versions and **counts** (stale nodes, duplicate names). Never copy a hostname, tailnet name, IP, user email or node id into the report. Use placeholders such as `node-a.example.invalid`.

| OS | Read-only commands |
| --- | --- |
| macOS (App Store or standalone app) | App present: `ls /Applications/Tailscale.app`. Version: `defaults read /Applications/Tailscale.app/Contents/Info.plist CFBundleShortVersionString`. The App Store build and the standalone build share that path; record which channel the owner says they installed. CLI, if present: `tailscale version`, `tailscale status --json`, `tailscale lock status`, `tailscale debug prefs`. |
| macOS / Linux CLI | Same four `tailscale` commands. Prefer `--json` on `status`. `tailscale debug prefs` is a local prefs dump (SSH / `RunSSH`, auto-update). Read `/etc/default/tailscaled` and systemd drop-ins for the **name** `TS_SSH_DISABLE_FORWARDING` and its boolean only. |
| Linux packages | `dpkg-query -W tailscale headscale` / `rpm -q tailscale headscale` / `apk info -e tailscale headscale`. ZeroTier: `zerotier-cli info` only if it is already installed and the command is local. NetBird: `netbird status` only if already installed; do not `up` or `login`. |
| Windows | `"$env:ProgramFiles\Tailscale\tailscale.exe" status --json` (and `version`, `lock status`, `debug prefs` if that build has them). Package list: `winget list Tailscale`. |
| Exported policy | Read the owner's exported HuJSON/JSON (`acl.hujson`, `policy.hujson`, Headscale policy). Look at `ssh` rules (`action` `accept`/`check`, `src`, `dst`, `users`), any forwarding fields on those rules, and `nodeAttrs`. Do not fetch policy from a control plane the owner did not export. |
| Headscale / ZeroTier / NetBird | Same class: is a remote-shell or privileged-forwarding grant present, and is it broad? If that overlay is absent, `NOT_APPLICABLE` with the empty package-query or missing binary as evidence. |

How to read Tailscale JSON without leaking identity:

- SSH enabled: prefs / status fields that mean "this node runs Tailscale SSH" (commonly `RunSSH` or an equivalent capability). Record true/false.
- Forwarding: policy rule fields or `TS_SSH_DISABLE_FORWARDING`. If the exported policy has no forwarding keys, record UNKNOWN, not "disabled".
- Broad rules: `src` contains `autogroup:member` (or a similarly wide autogroup) and `users` contains `root`. Quote those tokens only.
- Check mode: `action` is `check`. Record it; do not treat it as a fix.
- Tailnet Lock: `tailscale lock status` enabled/disabled. Do not copy signer names.
- Version and auto-update: `tailscale version` and prefs auto-update check/apply booleans.
- Stale or duplicate nodes: count peers with expired keys, long `LastSeen`, or repeated names. Write "2 expired keys, 1 duplicate name" — not the names.

osquery leads (not a substitute for the CLI): `processes` where name is `tailscaled` / `zerotier-one` / `netbird`; `listening_ports` joined to those processes.

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

When an advisory provides test hosts that serve the affected chain, test each client type separately. Each client has its own trust store, its own revocation data and its own way of building a chain.

**Only a live connection counts.** A client passes only when that client, making a real connection to the test host through its own networking stack, gets a certificate error. Verifying saved chain files offline (`openssl verify`, `security verify-cert` on PEM files, a script that parses the chain) is not enough. A live connection builds its own path: it may fetch or reuse intermediates and cross-signs that the saved chain does not contain, and it checks revocation online, often accepting the chain when a revocation server does not answer. Offline results can say "revoked" while the live connection succeeds. Use offline verification to explain a live result, never to replace one.

These live probes start `curl`, `python`, `node` or `bun`. That is the exception to the default "do not start those binaries" rule in [Bundled native libraries](#bundled-native-libraries). Confirm the on-disk binary is not a path inventory flagged as a suspect hijacked install before starting it.

| Client | Live probe |
| --- | --- |
| Safari and apps on Apple's URL loading system (macOS) | `nscurl https://test-host.example/` uses the same networking and trust stack as Safari. Also run the advisory's in-browser checker in Safari when it has one. |
| Built-in `curl`, `git`, `python3` (macOS and Linux) | `/usr/bin/curl -s -o /dev/null https://test-host.example/; echo $?` |
| Homebrew or other OpenSSL builds | That build's own `openssl s_client -connect test-host.example:443 -servername test-host.example` (read `Verify return code`) and its own `curl` |
| Python and pip | The interpreter's `urllib.request.urlopen("https://test-host.example/")`; for pip, `pip download --no-deps --index-url https://test-host.example/simple/ zzz-nonexistent` (a certificate error rejects, a "not found" means the TLS connection was accepted) |
| Node.js, Bun, Deno | `fetch("https://test-host.example/")` in that runtime |
| Java | A request from each JDK, for example with Java's built-in `HttpClient` in `jshell`. `keytool -printcert -sslserver` does not validate the chain. |
| Windows apps on Schannel | `Invoke-WebRequest https://test-host.example/ -UseBasicParsing` (record the exception) and `curl.exe` |
| Browsers | The advisory's in-browser checker in the user's real browser profile. A headless browser with a fresh profile lacks downloaded revocation data, such as Chrome's CRLSet, so its result is not the user's result. |

Rules for reading results:

- Count only a certificate-verification error as "rejected": curl exit code 60, an OpenSSL verify code other than 0, `CERT_REVOKED` or a distrust error from a runtime, a trust or revocation exception on Windows.
- A network failure, timeout or proxy error proves nothing. The check is BLOCKED or inconclusive, never PASS.
- Probe from the device itself. In a fleet, the probe runs inside the collection script, not from the auditor's machine.
- Also probe a known-good site that chains through the same CA family, so a fix that breaks legitimate chains shows up as a failure. An HTTP error such as 403 from that site still means the TLS connection succeeded.
- Repeat the same probes after any change and keep both results as before-and-after evidence.

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
