# Changelog

## Unreleased

### Added

- `scripts/host_checks.py`: one read-only check (88 checks total). `whmcs-82981` classifies self-hosted WHMCS against CVE-2026-82981 floors **9.0.10** / **9.1.2** from `includes/version.php` (WHMCS marker required; `configuration.php` presence only — never opened). Versions below 9.0 are info (outside this CVE). Never starts PHP or ionCube; never HTTP-probes the shopping cart.
- Evening extension of dated profile `host-advisories-2026-11-24.md`.
- Skipped as not host-checkable or already covered: VMSA-2026-0011 vCenter CVE-2026-123903..123907 (appliance; distinct from CVE-2026-123890), ICSA-26-323-02 Elecbrakes (already skipped), PlayStation Network ATO, McDonald's Japan app breach, Hugendubel / Tolino Cloud / eBook de, Rackspace Spot wind-down 8 Dec 2026 (update to the 17 Nov incident).

### Changed

- Briefing window through 24 Nov 2026 evening watch.
- Reviewed public hosts: `help.whmcs.com`, `blog.whmcs.com`, `docs.whmcs.com`, `status.spot.rackspace.com`, `www.heise.de`, `heise.de`, `0xbaas.com`.

## 0.4.15 - 2026-11-24

### Added

- `scripts/host_checks.py`: six read-only checks (87 checks total). `binary-parser-134814` classifies npm `binary-parser` against CVE-2026-134814 / GHSA-xmxc-6c22-m377 floor **2.3.1**. `leadstack-crm-connect` flags exact malicious `@leadstack/crm-connect` publishes plus leftover `~/.leadstack` / systemd unit names (no C2 host/IP stored). `monailabel-133968` classifies pip `monailabel` against CVE-2026-133968 / GHSA-qc22-rmgc-vg94 floor **0.8.6**. `gpgme-129975` classifies GPGME against CVE-2026-129975 floor **2.3.1** (Debian bookworm/trixie series floors; Gpg4win 5.1.2). `ghostscript-125396` classifies Ghostscript against CVE-2026-125396 floor **10.08.0** (Debian series floors). `idunno-anticsrf-131914` flags `Idunno.AntiCsrf.dll` by Mandiant MNDT-2026-0048 SHA-256 (or name/Web.config review); no vendor patch. Never starts node, monailabel, gpgme-tool, gpg, gs or IIS.
- Dated profile: `host-advisories-2026-11-24.md`.
- Skipped as not host-checkable or already covered: Azure APIM Classic credential theft, CVE-2026-134624 Mail Assure SSRF (hosted skip), SonicWall Gen6 EOL, React2STEAL, MoldyRoost iOS, SAP NetWeaver, Cisco Expressway, CERT-In AI-assisted attacks advisory, and named 24 Nov / queued breach-only incidents.

### Changed

- Briefing window through 24 Nov 2026.
- Reviewed public hosts: `lists.gnupg.org`, `www.gpg4win.org`, `safedep.io` (already present).
- `MAX_FILES_TARGET` 75 → 80 so the new dated profile stays under the compact-package warning.
- Review follow-up: `binary-parser-134814` / `leadstack-crm-connect` read nested installs from `node_modules/.package-lock.json` (malformed hidden locks are unknown, empty locks stay empty); `gpgme-129975` skips GPGMEPP/GPGMEQT bindings and applies Debian series floors only when upstream streams match; `ghostscript-125396` matches `libgsN*` (not `libgssapi-*`) with the same stream-aware Debian floors; `idunno-anticsrf-131914` marks Web.config collection truncation so a capped walk cannot PASS as complete.

## 0.4.14 - 2026-11-23

### Added

- `scripts/host_checks.py`: one read-only check (81 checks total). `bitwarden-cli-42994` classifies npm `@bitwarden/cli` **exactly 2026.4.0** (CVE-2026-42994 / GHSA-999x-2wm3-jfx8; unpublished malicious publish on 22 Apr 2026). Vendor floor **2026.4.1**. Range specs that can include 2026.4.0 are review. Leftover `bw_setup.js` / `bw1.js` (JFrog SHA-256s), `/tmp/tmp.987654321.lock`, `package-updated.tgz`, `/tmp/_tmp_`, unique `~/.bashrc` / `~/.zshrc` needles, and a cheap Dune-pattern git name/description hint remain findings after an upgrade. Scoped cache/pnpm paths use `cli-2026.4.0.tgz` / `@bitwarden+cli@`. Never starts `bw`, bun or gh. Exfil hosts and IPs are not stored.
- Dated profile: `host-advisories-2026-11-22.md`.
- Skipped as not host-checkable: unconfirmed Bitwarden-own GitHub Action CI claim, snap / native non-npm CLI, exfil URL/IP, locale kill switch, Runner.Worker memory scrape, and treating GHSA-g98r patched `None` as "no fix".

### Changed

- `bitwarden-cli-42994`: compound npm ranges (`||`, hyphen) are review so a leading `^2026.4.1` cannot hide `2026.4.0`; major-only `~2026` is review; `>2026.4.0-beta.1` is review while `>2026.4.0` stays info; an unreadable lock version is unknown (BLOCKED); leftover `bw1.js` is hashed up to 16 MiB; leftover names are looked up directly under `/tmp` and `/private/tmp` (no 5,000-entry listing slice); npm cache index reads record coverage gaps.
- Briefing window through 22 Nov 2026.
- Reviewed public hosts: `community.bitwarden.com`, `research.jfrog.com`, `www.stepsecurity.io`, `www.ox.security`, `socket.dev`, `www.ossprey.com`.

## 0.4.13 - 2026-11-22

### Added

- `scripts/host_checks.py`: four read-only checks (80 checks total). `openssl-121481` classifies OpenSSL 4.0/4.1 metadata against CVE-2026-121481 / GHSA-83xj-7xh4-4p7x floors 4.0.4 / 4.1.1 (CNA ranges; 3.x and LibreSSL/BoringSSL are info). `gpustack-102895` classifies the PyPI `gpustack` package against GHSA-gj9m-f8ph-pmhr / CVE-2026-102895 floor 2.2.0. `vmware-tools-123894` classifies Windows VMware Tools against VMSA-2026-0009 / CVE-2026-123894 floors 13.1.5 / 12.5.5 (12.4.10 is the named 32-bit floor; Linux `open-vm-tools` is not this CVE). `asus-acce-114202` classifies ASUS Control Center Express against CVE-2026-114202 floor 1.7.29 (Windows registry / Program Files; DisplayNames without Express are not this check). Never starts openssl, gpustack, VMware Tools or Control Center Express, and never HTTP-probes GPUStack.
- Dated profile: `host-advisories-2026-11-20.md`.
- Skipped as not host-checkable or already covered: PHP GHSA-gr4f-wgx5-jpfv (same floors as `php-129289`), VMware vCenter CVE-2026-123890 and SDDC Manager CVE-2026-123891/123892/123893 (appliances), CISA ICSA-26-323-01 OpenPLC Runtime, ICSA-26-323-02 Elecbrakes, ICSA-26-323-03 libumqtt, and 20 Nov 2026 breach-only incidents (JPMorgan/Visa/Mastercard third-party, Rakuten Securities, Prime Intellect DeepSeek v4.1 Flash swap, SBC Medical, BundID, Equinor, KPMG Canada).

### Changed

- `openssl-121481` binary banners keep prerelease suffixes such as `-dev` (4.0.4-dev / 4.1.1-dev are affected). An `opensslv.h` `OPENSSL_VERSION_*` value that is empty (`""`) or whitespace is `unknown` and does not abort binary or image inspection.
- `gpustack-102895` still skips Dockerfile FROM / `image:` operands as pip pins, but keeps `RUN pip install` specs as review evidence.
- `vmware-tools-123894` applies the 12.4.10 floor only to confirmed 32-bit installs (PE Machine, Wow6432Node, or Program Files (x86)); 64-bit and unknown-arch 12.4.x stay affected until 12.5.5. A native 32-bit uninstall row without Wow6432Node inherits the matching-version `vmtoolsd.exe` PE architecture.
- `asus-acce-114202` reads PE versions only from ACCE-named executables, not the first `.exe` in the tree.
- Briefing window through 20 Nov 2026.
- Reviewed public hosts: `isc.sans.edu`, `support.broadcom.com`, `www.asus.com`.
- `php-129289` records that GHSA-gr4f-wgx5-jpfv uses the same 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 floors.

## 0.4.12 - 2026-11-19

### Added

- `scripts/host_checks.py`: three read-only checks (76 checks total). `ruby2shell` classifies installed Ruby against GHSA-34m4-m9fh-gqp5 floors 4.0.10 / 3.4.13 / 3.3.14 (18 Nov 2026; 3.2 and older EOL). Distinct from `ruby-regex`. GitLab `version-manifest.txt` `ruby` is an info hint; BLOCKED unless another Ruby is affected (FAIL wins). The dpkg `ruby` dependency package is skipped. `php-129289` classifies PHP / PHP-FPM against GHSA-qc49-hpvq-g2w6 / CVE-2026-129289 floors 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36. Distinct from `php2shell`. php.ini is not this check. dpkg `php` / `php-fpm` default-version packages are skipped. `drupal-132165` classifies Drupal core against SA-CORE-2026-017 / CVE-2026-132165 floors 10.6.22 / 11.3.22 / 11.4.13 from `composer.lock`, `installed.json` and `core/lib/Drupal.php`. `composer.json` is not evidence. Never starts ruby, php-fpm or drush, and never HTTP-probes `install.php`.

### Changed

- `php2shell` ini wording: CVE-2026-115560 now also has 19 Nov 2026 patched releases (`php-129289`); mitigation remains `session.upload_progress.enabled=0`.
- Dated profile `host-advisories-2026-11-19.md` extended for the evening watch.
- Reviewed public hosts: `www.ruby-lang.org`, `ruby-lang.org`, `verialabs.com`.
- Skipped as not host-checkable or already covered: CVE-2026-115560 as a second check, PostgreSQL CVE-2026-116331 (already `postgresql-6460`), MySQL CVE-2026-101786, ClickHouse Depthfirst PoC, Oracle Text / ORDS, European Commission ARTEX incident, N-able Mail Assure hosted cloud.
- GHSA-34m4 source URL is the ruby/ruby repository advisory (the generic github.com/advisories path 404s). GitLab bundled ruby is BLOCKED when the manifest names it and no other Ruby is affected; FAIL still wins if another Ruby is affected. Drupal.php discovery requires `core` and `core/lib` to be plain directories. dpkg default-version `php` / `ruby` dependency packages are skipped (`php8.4-fpm` / `ruby3.3` and apk/rpm `php` / `ruby` stay).

## 0.4.11 - 2026-11-19

### Added

- `scripts/host_checks.py`: two read-only checks (73 checks total). `litellm-40217` classifies installed and pinned LiteLLM against GHSA-wxxx-gvqv-xp7p / CVE-2026-40217 (CISA KEV 18 Nov 2026; range 1.81.8 to before 1.83.10; `first_patched_version` 1.83.10; advisory body also names 1.83.11). Distinct from `litellm-1-107-0` and `artex-gateway-keys`. `nginx-123007` classifies nginx OSS metadata against 1.30.7 (stable) and 1.31.9 (mainline) for CVE-2026-123007 and the 18 Nov 2026 nginx.org set. Older trains below those floors are affected. OpenResty and NGINX Plus are review, including Windows uninstall DisplayNames that match `nginx` or `openresty` (Plus / OpenResty are review). Distro backports may keep an old version string. Version comes from package DB, Homebrew, PE resources or ASCII `nginx/X.Y.Z` in binary bytes (optional `rc`/`pre` suffix is kept so `1.30.7rc1` is not treated as 1.30.7). Never starts LiteLLM or nginx. `nginx-present` is unchanged.
- Dated profile: `host-advisories-2026-11-19.md`.
- Skipped as not host-checkable: Synology DSM / BeeStation CVE-2024-10441, REDCap CVE-2026-90817, F5 BIG-IP TMM flaws, TfL Oyster photocard breach. Axis CVE-2026-90436 remains `axis-90436`.

### Changed

- Briefing window through 19 Nov 2026.
- Reviewed public hosts: `nginx.org`, `radar.cloudflare.com`, `www.wiz.io`, `xint.io`, `www.x41-dsec.de`.
- `MAX_FILES_TARGET` 70 → 75 so the new dated profile stays under the compact-package warning.

## 0.4.10 - 2026-11-18

### Added

- `scripts/host_checks.py`: eleven read-only checks (71 checks total). `artex-gateway-keys` records LiteLLM / Dify / One API credential **field names** only (ARTEX). `vcenter-log4shell` classifies vCenter metadata against Broadcom KB 87081 (7.0 U3c 19234570 / 6.7 U3q 19300125 / 6.5 U3s 19261680). `axis-90436` flags Axis 1.x jars (EOL, no 1.x fix) and Confluence DC below 9.2.28 (CVE-2026-90436; 10.x info; Remote API off is mitigation). `ncentral-hf3` classifies on-prem N-central below 2026.4.1.39 (HF2 2026.4.1.26 is not a fix; hosted NCOD skipped). `blank-canvas-vsx` matches 131 Microsoft RemovedPackages 11/03/2026 Malware extension ids. `apple-65339` classifies macOS ProductVersion against HT148281 Tahoe 26.6.2 and HT149043 Sequoia 15.8 (iOS skipped). `agent-framework-1-26` classifies malicious PyPI 1.26.1 / 1.26.2 plus named IOC file hashes; sibling unpinned pins are a lead; the exfil URL is not stored. `java4shell-114938` classifies OpenJDK metadata against v17.0.21.1 / v21.0.13.1 / v25.0.5.1 / v27.0.1.1 (17.0.6–17.0.21 affected; 8/11 not this CVE except 8u511-perf). `puppet-115731` classifies PE 2023.8.13 / 2025.12.1 / 2026.0.1 and Core 9.1.3 / 8.22.2 (CISA KEV 17 Nov 2026; 8.22.1 is review). `roller-129448` classifies Apache Roller below 6.1.6 (CVE-2026-82384 / CVE-2026-129448; 6.1.5 still affected; web.xml is mitigation). `mysql-114952` classifies MySQL Server metadata against Oracle Nov 2026 CSPU ranges (8.4.0–8.4.13, 9.7.0–9.7.4, 26.10; Cluster also 8.0.0–8.0.50); MariaDB and mysql-client are not this check. Never starts java, mysql, mysqld, vpxd, puppet or N-central.
- Dated profile: `host-advisories-2026-11-18.md`.
- `references/saas-identity.md`: Google Workspace Super Admin takeover (Cold Relic) is tenant/admin-console only.

### Changed

- Host-check review follow-up: Confluence jar names require a regular `confluence-N.N.N.jar` (not `.bak`) and unknown per install directory; N-central unknown per Windows install; ARTEX image findings come only from FROM/`image:` lines and omit the image string; MySQL moving tags (`latest`, `8.4`) are unknown rather than a false PASS; MySQL Cluster matches `mysql-cluster`/`ndb` names only; Java Homebrew kegs read `libexec` release files and classify `8u511-perf` image tags; `ncentral-hf3` and `java4shell-114938` depend on the file walk; `agent-framework==1.26.*` is review.
- Host-check review follow-up (round 2): FROM/`image:` matching uses the image operand (not stage aliases); Confluence classifies every `confluence-N.N.N.jar`; Blank Canvas requires a complete version suffix (optional VS Code platform); sibling `==1.26.*` pins are review; Roller `version.properties` without a version key is unknown; N-central and Puppet whitespace version files no longer abort the check; quoted ARTEX field names are recognized; image checks for Confluence, N-central, agent-framework, Java, Roller and MySQL use `docker_decl_refs`; Darwin without ProductVersion is unknown; an incomplete `py_installs` scan is BLOCKED; FAIL still exports truncated evidence when the walk stopped.
- Host-check review follow-up (round 3): an unlistable Python environment is incomplete, not empty; `FROM` accepts a tab; quoted Compose `image` keys match and `environment.image` does not; digest-pinned image tags are unknown, not patch evidence; unreadable existing Puppet `pe_version`/`VERSION` files are unknown; bare ARTEX `password`/`key`/`secret`/`token` field names are recognized; Roller `roller-version.properties` without a version key is unknown; Java moving tags (`eclipse-temurin:17`) are unknown; `agent-framework==1.26.2` matches a trailing extra `.0` by version identity (`===` stays distinct).
- Host-check review follow-up (round 4): `===` pins keep the `===ver` representation and match malicious versions by exact string (`litellm===1.107.0` and `agent-framework===1.26.1`/`===1.26.2` are affected). Identity matching still applies only to `==` pins.
- Briefing window through 18 Nov 2026.
- Reviewed public hosts: `aws.amazon.com`, `safedep.io`, `openjdk.org`, `confluence.atlassian.com`, `status.n-able.com`, `knowledge.broadcom.com`, `www.puppet.com`, `roller.apache.org`, `cloud.google.com`.
- Claude Code VSX 2.1.312 needs no second floor (`claude-code-vsx-21313`). Quay CVE-2026-110697 is the same RHSA set as `quay-123710`.

## 0.4.9 - 2026-11-16

### Added

- `scripts/host_checks.py`: two read-only checks (60 checks total). `postgresql-6460` classifies PostgreSQL core-server metadata with `parse_version` / `classify_lines` against CVE-2026-6460 floors 18.7, 17.12, 16.16, 15.20, 14.25 (PostgreSQL CVE page and news 3442, 12 Nov 2026). Major `< 14` is affected; 19 RC 1 is affected; 19 RC 2 and later are info. The dpkg `postgresql` metapackage and `libpq-dev` headers are not this check. `postgresql-client` / `libpq` / `postgres-exporter` are not this check. `PGDATA/PG_VERSION` is unread. Never starts postgres. `quay-123710` classifies `quay/quay-rhel8`, `quay/quay-rhel9` and `projectquay/quay` image tags against RHSA floors 3.9.28, 3.10.28, 3.12.24, 3.14.10, 3.15.9, 3.16.7, 3.17.7, 3.18.3 (CVE-2026-123710). Operator images and missing 3.11 / 3.13 / 5.x trains are review. Restricting `/keys` is mitigation. Never HTTP to `/keys`.
- Dated profile: `host-advisories-2026-11-16.md`.
- `scripts/host_checks.py`: one read-only check (58 checks total). `unrealircd-114713` classifies installed UnrealIRCd with `parse_version` / `at_least` against v6.2.7.1 (CVE-2026-114713, CISA KEV 13 Nov 2026). 6.2.7 is not fixed. ASCII `hot-patch-bundle-20261107` in labeled-response module/source is the hot-patch signal; `./unrealircd module-status` is never run. UnrealIRCd 5 without that token is affected; 3.x/4.x are review. `blacklist-module` is mitigation. Never starts the daemon.
- Dated profile: `unrealircd-2026-11-08.md`.

### Changed

- `claude-code-vsx-21313` classifies tampered Cursor Marketplace Anthropic.claude-code **2.1.312 and 2.1.313** as affected (13 Nov incident update; 30 Oct notice already named both). Persistence IOCs unchanged. Support-credential rotation is not part of the host check.
- `unrealircd-114713`: backup `labeled-response*` names, uncompiled source (including `modules/*.c`), extensionless `labeled-response` files, and a token in another prefix next to a live unpatched module are not hot-patch evidence; an unreadable candidate module or a `modules/third` path that cannot be listed or is not a directory is unknown even if another candidate carries the token; Windows ignores the token (vendor: upgrade only); a distro package at the floor is not BLOCKED by a metadata-less `/usr/lib/unrealircd` or `/etc/unrealircd`.
- `claude-code-vsx-21313`: a non-string `package.json` `version` does not abort the persistence IOC checks.
- Briefing window through 16 Nov 2026.
- Reviewed public hosts: `forums.unrealircd.org`, `www.unrealircd.org`, `www.postgresql.org`, `postgresql.org`, `quay.io`.
- `postgresql-6460`: skip the dpkg `postgresql` metapackage; do not classify `libpq-dev` `/usr/include/postgresql/pg_config.h`; treat 19 RC 1 as affected (19 RC 2 remains the 19-line fix); skip rpm `postgresql` / `postgresqlN` clients and classify `postgresql-server` / `postgresqlN-server`; match dpkg `postgresql-9.6`.

## 0.4.8 - 2026-11-05

### Added

- `scripts/host_checks.py`: two read-only checks (57 checks total). `openssh-musl-pwauth` classifies Alpine `openssh-server` / `openssh-server-pam` with `hostscan.apk_version_cmp` against the 5 Nov 2026 Alpine floors (3.16–3.24 plus edge `10.6_p2-r0`) and non-Alpine musl hosts with `hostscan.openssh_portable_cmp` against portable OpenSSH 10.6p2. Alpine `ID` is enough musl evidence; non-Alpine needs a regular musl loader and no glibc loader. `UsePAM` first-wins; `PasswordAuthentication no` is mitigation. Never reads shadow or starts sshd. `litespeed-cache-93389` classifies only `litespeed-cache.php` `Version:` with `parse_version` / `at_least` against 7.9.2 (CVE-2026-93389). A missing main file is unknown (BLOCKED). No Store API HTTP.
- Dated profile: `host-advisories-2026-11-05.md`.
- `hostscan.py`: `parse_apk_version`, `apk_version_cmp`, `parse_openssh_portable`, `openssh_portable_cmp`.

### Changed

- `activestorage-122006`: release lines newer than the GHSA-named 8.0 / 8.1 trains use distinct review text; lines below 8.0 keep the current GHSA wording.
- `jetbrains-jbr-emudhra`: `JB_PRE_RE` matches `EAP9` / `RC1`; `_jb_looks_like_app` is prefix-only (`JetBrains ` + name or the name); Windows `Program Files\JetBrains` children without `product-info.json` are unknown only when they look like a JetBrains app.
- `MAX_FILES_TARGET` 65 → 70 (`MAX_FILES_ERROR` stays 100).
- Briefing window through 5 Nov 2026.
- Reviewed public hosts: `alpinelinux.org`, `www.openssh.org`, `blog.litespeedtech.com`, `www.wordfence.com`.

## 0.4.7 - 2026-11-05

### Added

- `scripts/host_checks.py`: four read-only checks (55 checks total). `apt-109518` classifies the installed `apt` package with a Debian Policy 5.6.12 comparator (`hostscan.debian_version_cmp`) against USN-8996-1 / DSA-6607-1 / DLA-4880-1 floors (Ubuntu 26.10/26.04/24.04/22.04 plus ESM 20.04/18.04/16.04/14.04; Debian 13 `3.0.4` and 12 `2.6.2`). Linux without `apt`, Debian 11 and older, and non-ubuntu/debian IDs are handled as specified; apt.conf is not read. `apple-27834` classifies macOS `ProductVersion` and desktop Safari against HT214106 (Sonoma 14.5) and HT214103 (Safari 17.5); CISA KEV added CVE-2024-27834 on 4 Nov 2026. `activestorage-122006` classifies `Gemfile.lock` GEM specs (v8.0.5.2 / v8.1.4.1); GIT/PATH, platform suffixes and `mini_magick` below 5.1 are review. `better-auth-2026-11-03` classifies `better-auth` and five `@better-auth/*` packages (1.7.16 / `1.8.0-beta.5`).
- Dated profile: `host-advisories-2026-11-04.md`.
- `hostscan.py`: `parse_debian_version`, `debian_version_cmp`, `gem_lock_versions`, `better_auth_beta_n`. `Index.gem_lock` skips `vendor/bundle/`, `.bundle/` and `gems/<name>-<version>/`.

### Changed

- Reviewed public hosts: `lists.debian.org`, `security-tracker.debian.org`, `rubyonrails.org`, `xenbits.xen.org`, `better-auth.com`, `www.openwall.com`.

## 0.4.6 - 2026-11-03

### Added

- `scripts/host_checks.py`: two read-only checks (51 checks total). `nodered-admin-http` classifies Node-RED editor auth from `settings.js` (comment-stripped `adminAuth` / loopback `uiHost` / deprecated `httpAdminAuth`) plus package, global `node-red/package.json`, systemd unit names, and `/proc/<pid>/comm`. Siemens Industrial OS / SIMATIC / IoT2050 markers with Node-RED are extra review (SSA-834709 firmware V4.3.4.1 is not compared). `cryptopayment-gateway-81648` classifies only `cryptopayment-gateway.php` (WPScan 1.2.1-1.2.2 affected; any other parsed version review; no fixed release).
- Dated profiles: `nodered-siemens-2026-08-11.md`, `cryptopayment-gateway-2026-09-10.md`.

### Changed

- `linux-tcp-uaf-98432` now classifies Ubuntu generic ABI rows (proposed / WIP / pending) and RHEL NVRs only when `ID=rhel` and the dist tag is `el8_10`, `el9_8` or `el10_2`. Ubuntu at or above a proposed ABI is review, not a released `-updates`/`-security` fix. Ubuntu 26.10 stays review. Title no longer says "review only".
- Shared helper `ubuntu_generic_abi_state` (Fragnesia unchanged).
- Reviewed public hosts: `cert-portal.siemens.com`, `nodered.org`, `access.redhat.com`, `wpscan.com`.
- `profiles/golang-mptcp-2026-10-29.md` and `profiles/dev-endpoint-2026-10-30.md`: Ubuntu fixes in -proposed (2 Nov 2026); RHEL fixed via RHSA-2026:93412/93413/93414 (1 Nov 2026).
- `nodered-admin-http`: `adminAuth` set to `false`, `null` or `undefined` counts as no adminAuth. Plain `'` / `"` quote state ends at a newline.

### Known limits

- A backtick template string containing an apostrophe followed by `/*` on the same line can still hide a commented `adminAuth` block.

## 0.4.5 - 2026-11-02

### Added

- `scripts/host_checks.py`: read-only check `lxd-112816` (49 checks total). Classifies Canonical LXD and MicroCloud snap metadata against Discourse 90557 / CVE-2026-112816 floors (LXD 6.10.1, 5.21.9, 5.0.11, 4.0.15; MicroCloud 3.4.1, 2.1.5). The active snap revision is the `current` symlink text; retained revisions are info. Distro `lxd` / `microcloud` packages are review. Related Incus is classified from `incus` / `incus-base` packages (GHSA-xg75, `>= 7.6.0`) or `/var/lib/incus`; `/snap/incus` is not read. Incus 6.0 LTS is review. Presence without version uses `/var/snap/lxd/common/lxd`, `/var/snap/microcloud/common`, or `/var/lib/incus`. It never starts `lxc`, `lxd`, `incus`, `microcloud` or `snap`.
- Dated profile: `lxd-microcloud-2026-10-28.md`.

### Changed

- Reviewed public hosts: `discourse.ubuntu.com`.
- `MAX_FILES_TARGET` 60 → 65 so the new dated profile stays under the compact-package warning.

### Known limits

- Homebrew and Chocolatey `incus`/`lxc` are clients and are not classified.
- Container image references are not classified for this check.
- `/var/lib/lxd` is ignored (deb-era leftover after `lxd.migrate` on older Ubuntu).
- Retained older revisions are info. Only the revision `current` points at is classified.

## 0.4.4 - 2026-10-31

### Added

- `scripts/host_checks.py`: three read-only checks (48 checks total). `jetbrains-jbr-emudhra` classifies JetBrains IDEs, Gateway, Toolbox, ReSharper, standalone JBR (macOS) and `jetbrainsd` against the 30 Oct 2026 blog floors. IDE versions come only from `product-info.json`. RC/EAP is review. An IDE on line 2025.2 at or above its floor is JCEF-pending review. `clickhouse-116366` classifies `clickhouse-server` and `clickhouse-common-static` against the four OSS floors for CVE-2026-116366 (`line_len=2`). Cloud / BYOC numbers are not OSS floors. Moving image tags are info. `wordpress-core-upgrade-rce` classifies `$wp_version` against GHSA-4w3m-c66w-69mg / HelpHub 7.1.4 backports through 4.7.39. 7.2 prereleases follow the Beta 3 rule. Staged copies under `wp-content/upgrade` are review. None of these checks start a program or make an HTTP request.
- Dated profiles: `jetbrains-jbr-emudhra-2026-10-30.md`, `clickhouse-2026-10-30.md`, `wordpress-core-upgrade-2026-10-28.md`.

### Changed

- Reviewed public hosts: `blog.jetbrains.com`, `blog.cloudflare.com`, `clickhouse.com`, `wordpress.org`, `www.wordpress.org`.
- `profiles/emudhra-2026-10-17.md` points at the JetBrains JBR check; OS-store reporting is unchanged.
- `clickhouse-116366` does not treat `clickhouse-common-static` as server evidence on a client-only or keeper-only install (those packages pull the shared static package). An orphan `clickhouse-common-static` is still classified.

### Known limits

- `jetbrains-jbr-emudhra` matches RC/EAP only as a separate word, so a suffix like `EAP9` or `RC1` reads `affected` instead of `review`. It still FAILs.
- An unrelated macOS app whose name contains a JetBrains product name (for example `Gateway`) and has no `product-info.json` reads `unknown`.
- On Windows, a non-IDE folder under `Program Files/JetBrains` with no `product-info.json` reads `unknown`.
- The package file count is at its target of 60. The next profile needs a higher target or a merged profile.

## 0.4.3 - 2026-10-30

### Added

- `scripts/host_checks.py`: read-only check `drupal-commerce-118539` (45 checks total). Classifies Drupal Commerce Core against SA-CONTRIB-2026-254 / CVE-2026-118539 floors 8.x-2.41 and 3.3.13 from `composer.lock`, optional `vendor/composer/installed.json`, and packaged Commerce info.yml (`project: commerce` only). `composer.json` is not evidence. Dev builds and lines outside 2.x/3.x are review. Drupal 7 commerce INI files are out of scope. A same-site fixed lock turns an unversioned info.yml into a note. An unreadable needed file is BLOCKED.
- `scripts/inventory.py`: `drupal_commerce_hints` for a `drupal/commerce` lock pin or packaged Commerce info.yml. Empty hints are not runtime absence.
- Dated profile: `drupal-commerce-2026-10-28.md`. Order-inconsistency audit is a SKIPPED row (needs the site database).

### Changed

- Reviewed public hosts: `www.drupal.org`, `drupal.org`.
- `drupal-commerce-118539` normalises BOM/CRLF in info.yml; pairs an unversioned or unpackaged info.yml only with the deepest enclosing lock/installed.json root when the relative path is a Drupal module layout (case-insensitive); reports unpackaged git checkouts as unknown unless that pairing holds; treats a lock mention as `drupal/commerce` only when a package is named `drupal/commerce`; skips a `vendor` directory only when it contains `autoload.php` or `composer/installed.json`; names blocked-read causes (too large, invalid JSON, cannot read); treats numeric `*-dev` pins (including `-dev+build`, `-dev1`, `-DEV`) as review; treats a `#` remainder (`3.3.13-rc1#local`) as review; treats an unreadable nonempty `version:` line as unknown rather than pairing it; reviews differing `version:` lines and a packaged Commerce info.yml that names another project. The info.yml `version:` matcher is linear-time and still reads padded quoted values. Inventory uses the same vendor, name, and newline rules.

### Known limits

- The Composer vendor-tree marker walk can look above the scan root.
- A git checkout paired with a fixed lock can hide an older commit (compare `.git/HEAD` with the lock's `source.reference` later).
- `host_checks` and `inventory` Commerce helpers are duplicated.
- Inventory gives no hint for an invalid-JSON lock that names `drupal/commerce`.
- An unreadable second `version:` line next to a readable one is ignored.

## 0.4.2 - 2026-10-30

### Added

- `scripts/host_checks.py`: three read-only checks (44 checks total). `teamviewer-111585` classifies TeamViewer metadata against TV-2026-1011 / CVE-2026-111585 (15.83; 15.64.10 on Windows 7/8; 14.7.48868; platform 13.2 floors). Host findings cite TV-2026-1011. Portable folders under Downloads/Desktop and present-but-unversioned installs are covered. It never starts TeamViewer and does not read under `/opt/teamviewer`. `fragnesia-linux` classifies the running Linux kernel for CVE-2026-46300 from the CVE record floors and the Ubuntu official `x.y.0-N-generic` release + kernel-series table (including HWE and `#NNN[~suffix]-Ubuntu` upload). Mainline-PPA kernels remain review-only. An unreadable running osrelease when other kernel metadata is present is unknown. It never emits info "Not affected" from `VERSION_ID` alone. `linux-tcp-uaf-98432` records the running kernel and distro as review: Ubuntu last updated 29 Oct 2026 had no released fixed build; cve.org floors published 15 Oct 2026, updated 30 Oct 2026 are not Ubuntu floors.
- Dated profiles: `teamviewer-2026-10-27.md`, `fragnesia-2026-10-28.md`. Skipped-list rows for the DHS staff identity leak and Synology NAS ransomware reports.

### Changed

- `profiles/golang-mptcp-2026-10-29.md` cites Ubuntu CVE-2026-98432 (last updated 29 Oct 2026) and the cve.org record published 15 Oct 2026, updated 30 Oct 2026: no released Ubuntu fixed package; upstream floors are not Ubuntu floors; WIP targets are not floors; the running-kernel record is `linux-tcp-uaf-98432`.
- Reviewed public hosts: `www.teamviewer.com`, `teamviewer.com`, `ubuntu.com`, `www.ubuntu.com`, `lists.openwall.net`, `remedio.io`.
- `check_public_package.py` compact file-count target raised from 55 to 60.

## 0.4.1 - 2026-10-30

### Added

- `scripts/host_checks.py`: four read-only checks from the 29–30 Oct 2026 briefing (41 checks total). `claude-code-vsx-21313` looks for Anthropic.claude-code 2.1.313 and the vendor-named persistence indicators (key comment only; no key material). `yoba-fake-ai-apps` looks for the Check Point Yoba sideload layout. `huggingface-qwen2-tiny` lists named cache paths as `unknown` (unconfirmed lead). `go-mptcp-linux` records Go 1.24+ on Linux and `godebug multipathtcp=0`; it does not invent a kernel version for CVE-2026-98432.
- `scripts/inventory.py`: `untrusted_run_interpolations` on GitHub workflow files when untrusted `github.event` / `github.head_ref` text is interpolated into a `run:` step. Numeric fields and `env:` assignments are not listed.
- Dated profiles: `dev-endpoint-2026-10-30.md`, `claude-code-vsx-2026-10-29.md`, `golang-mptcp-2026-10-29.md`, `freebsd-wireguard-2026-07-29.md`.

### Changed

- `gitlab-self-hosted` now classifies CE/EE 19.2 / 19.3 / 19.4 against the NVD floors for CVE-2026-97229 (CISA KEV, 29 Oct 2026). Versions outside that range stay `review`.
- Briefing date stamped on host-check fragments is 2026-10-30. A human must still re-read primary sources before closing findings.
- Host-check review fixes: crontab `.smt` uses a word-boundary match; `HF_HOME` is resolved to its `hub` subdirectory; Go `VERSION` is the first line only; standalone `go.mod` files are indexed. Inventory `untrusted_run_interpolations` flags untrusted github refs anywhere in an expression and ends a `- run:` block at the `run` key so a same-level `env:` is not treated as script.

## 0.4.0 - 2026-10-30

### Added

- Four host checks for the 2026-10-28 briefing items, taking the bundled set from 33 to 37:
  - `tailscale-ssh-1104`: Tailscale SSH forwarding (TS-2026-014 to TS-2026-017). Fixed in 1.104.4. Reads package/app metadata, prefs `RunSSH`, the `TS_SSH_DISABLE_FORWARDING` name in service files or tailscaled environ, and exported `ssh` policy keys. Never runs `tailscale` or restarts `tailscaled`.
  - `peoplesoft-presence`: Oracle PeopleSoft / PeopleTools footprint for CVE-2026-35273. Presence is `review` (a patched host may keep the same PeopleTools version). No PIA probe.
  - `anthropic-ai-chain` (unconfirmed): browser and OS patch level against a dated Chrome 156 floor. Safari, Windows and Linux exact builds are recorded as unverified. The Anthropic research post is real; mapping a given host to those chains is not.
  - `gmo-onamae-presence`: local zone/config hints for Onamae Desktop Cloud / DNS. No live DNS. Generic "GMO" text is not a hit.
- `inventory.py` emits `peoplesoft_hints` and `gmo_onamae_hints`, and records `actions/setup-node` `node-version` pins as runtime hints.
- Dated profiles: `peoplesoft-2026-10-28.md`, `anthropic-ai-chain-2026-10-27.md`, `gmo-onamae-2026-10-21.md`.

### Changed

- `brotli-nodejs` also classifies `.nvmrc`, `.node-version`, `.tool-versions`, `package.json` `engines.node` and CI `setup-node` pins. In-the-wild use against Node 24.22.0 is labelled unverified (not a Node.js or NVD claim).
- Mesh-VPN profile last-checked 2026-10-28: Tailscale published bulletins TS-2026-014..017 and named 1.104.4. No CVE id. `TS_SSH_DISABLE_FORWARDING=1` is the vendor-documented mitigation when a host cannot update.
- Example baseline / after-fix reports include the four checks as `BLOCKED`: empty inventory hints are not runtime or Onamae-non-use evidence. Tailscale, Anthropic and GMO sources published after the baseline date are omitted from the baseline and kept on the after-fix report.
- Reviewed public hosts: `www.oracle.com`, `oracle.com`, `www.anthropic.com`, `anthropic.com`, `internet.gmo`.
- `check_public_package.py` compact file-count target raised from 40 to 50 for the new dated profiles.
- Host-check report fragments stamp `retrieved_on` with `--collected-on` (this run does not fetch advisories).
- VALIDATION.md and `references/ci-failure-modes.md` record CI failure modes for the unchanged test workflow (bytecode cache, macOS temp symlinks, Windows BLOCKED helpers, expected INCOMPLETE after-fix example, host-check smoke bounds).

## 0.3.1 - 2026-10-29

### Added

- `references/ci-failure-modes.md`: troubleshooting notes for the public test workflow (bytecode cache, macOS temp symlinks, Windows BLOCKED helpers, expected INCOMPLETE after-fix example).

### Changed

- Phase 2, SaaS/identity, scoped-checks, reporting and contributing notes: treat single-source and press-only reports as unconfirmed leads. They can set identity and messaging-tenant checks to `BLOCKED` and open related findings as `unknown`; they cannot confirm a breach or clear one. Example: the TechRadar report published 28 Oct 2026 (retrieved 29 Oct 2026).
- `validate_report.py` rejects `vulnerable_component` findings that cite only a non-primary or stale source. After-fix reports also reject a primary advisory retrieved before the baseline (`retrieved_on` must be on or after the baseline `generated_on`). Same-day retrievals count as this run. The refresh rule applies only to primary advisory kinds. Nested baseline checks skip the new primary-source rule so a historical baseline that only cited non-primary sources is not made invalid; empty `source_ids` on a component finding is still `SOURCE_MISSING`.

## 0.3.0 - 2026-10-27

### Added

- `scripts/host_checks.py`: read-only checks of the machine it runs on (macOS, Linux, Windows) for the 2026-10-27 developer-endpoint briefing: 33 checks covering testmetest hooks, payload blobs and package, planted `AGENTS.md`/`CLAUDE.md`, MCP servers and base URLs in coding-agent configs, `function-color`, LiteLLM 1.107.0, Brotli CVE-2026-111497 (Node, Python, .NET), eMudhra (certifi and trust stores), Chrome 156 and browser versions, PHP2Shell, and the briefing's "check if we use it" items. It never runs the programs it checks, makes no network calls, writes only `--out`, redacts config values, and is bounded by depth, entries and time. It can emit `report_fragments` to merge into a report.
- `scripts/hostscan.py`: the bounded, no-follow walker and metadata parsers behind it (Python dist-info, conda, lockfiles, PE and Go build info, plists, DER/PEM, git index and pack headers, LFS patterns).
- `references/host-checks.md` (how to run it, per-OS coverage, limits) and `profiles/dev-endpoint-2026-10-27.md` (dated briefing facts, sources and skipped items).
- Fixture tests for every check on simulated macOS, Linux and Windows hosts, and a whole-run test proving no writes, no network, no subprocess beyond two read-only listings, and no secret values in output.
- CI runs on Windows (Python 3.9 and 3.14) alongside Ubuntu and macOS, and adds a host_checks smoke run on each runner.

### Changed

- Tests for the POSIX-only helpers (`inventory.py`, `check_public_package.py`, `render_report.py --out`) are skipped where those helpers exit BLOCKED, so the suite runs on Windows.
- Briefing source hosts added to the reviewed public-host list used by the leak scanner.
- Host path helpers treat POSIX `/home/...` locators the same on every OS, keep simulated PATH entries that already sit under `sysroot`, and de-duplicate `Lib`/`lib` site-packages on case-folding volumes. `display()` redacts the original locator before POSIX `abspath` of a drive-prefixed `/home` path.
- `py_pins` ignores `#`-comments so a commented pin is not treated as installed.
- `pe_file_version` still scans the head of a file larger than the read window (the tail-only pass used to abort).

## 0.2.x - 2026-10-25 to 2026-10-26

- Added bundled-library and hijacked-package checks (Brotli, LiteLLM, eMudhra) with dated profiles.
- Added mesh VPN SSH, PHP runtime and hosted AI/ML credential checks and profiles.

## 0.2.0 - 2026-10-22

- First public release: phases and gates, report schema, validator, renderer, inventory, public-package checker, endpoint and fleet guide.
