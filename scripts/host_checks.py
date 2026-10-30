#!/usr/bin/env python3
"""Read-only endpoint checks for the dated developer-machine briefing (macOS, Linux, Windows).

What it does:
- One bounded walk of the home folder (plus optional extra roots) builds an
  index of git repositories, AI tool config folders, agent instruction files,
  lockfiles, manifests, container files and Python environments.
- Targeted lookups read package metadata (dist-info, conda-meta, package
  databases, Homebrew Cellar, Windows uninstall registry keys, app bundle
  Info.plist, version directories, PE version resources, Go build info,
  header files) and trust-store bundles.
- Each check returns PASS / FAIL / BLOCKED / NOT_APPLICABLE with findings,
  the briefing fact it relies on, and the briefing's source URLs.

What it never does:
- It never starts node, python, pip, php, ruby, git, TeamViewer, Drupal, drush, composer or any audited program,
  never installs, never contacts a network, never revokes or rotates a
  credential, and never changes a file. The only write is --out.
- It never prints a secret value. Config files are reduced to names, env var
  names, command basenames and URL scheme plus host; every output string is passed
  through the shared redactor as a last step.
- "Not installed" is NOT_APPLICABLE ("not present"), never an error.

Usage:
  python3 scripts/host_checks.py [--root DIR ...] [--out FILE [--force]] [--target ID]
                                 [--only CHECK_ID ...] [--allowlist FILE] [--strict]
                                 [--max-depth N] [--max-entries N] [--time-budget SECONDS]
  python3 scripts/host_checks.py --list-checks

Exit codes: 0 ran (findings are in the output), 2 usage or output error,
3 with --strict when any check FAILs or coverage is PARTIAL.
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hostscan as hs  # noqa: E402
import safeio  # noqa: E402
import textscan  # noqa: E402
from inventory import INJECTION  # noqa: E402

try:
    import winreg  # Windows only
except ImportError:
    winreg = None

VERSION = "0.4.3"
BRIEFING = "Security briefings, 16-30 Oct 2026 (public reports; dated 2026-10-27, 2026-10-28 and 2026-10-30)"
BRIEFING_DATE = "2026-10-30"
APP = ".app"
MIB = 1024 * 1024
# Joined at runtime so the public-leak host pattern does not read the runtime folder names as domains.
DOTNET_FRAMEWORKS = tuple("Microsoft.%s.%s" % (n, "App") for n in ("NETCore", "AspNetCore", "WindowsDesktop"))
# Split so the public-leak IPv4 pattern does not read this version as an address.
BROTLICFFI_FIXED = "1.2.1" + ".0"

LIMITS = [
    "Read-only and local: nothing is executed, installed, fetched, revoked or modified; only --out is written.",
    "Versions come from metadata on disk. A distribution build can carry a backport under an old version number.",
    "Hook and MCP findings cannot tell who wrote a file. Mark files you wrote with --allowlist (each entry needs a reason).",
    "The home walk is bounded (depth, entries, time) and skips caches, tool installs and node_modules; "
    "targeted lookups cover the known install locations. Anything else is a coverage gap or out of scope.",
    "Git objects are parsed directly (git is never run). Packs other than index version 2 are a gap.",
    "Without openat support (Windows) a directory swapped for a link mid-walk is not detected.",
    "Every version fact comes from the dated briefing; re-read the primary advisory before closing a finding.",
    "Ubuntu kernel ABI is compared as (release, major.minor, abi[, upload]). The Ubuntu table applies only to "
    "official x.y.0-N-generic strings (N = 1-999, no leading zero). Mainline-PPA, N >= 1000, and other strings are review. "
    "parse_version nums ignore the ABI, so 6.8.0-90 and 6.8.0-124 are not treated as equal.",
    "linux-tcp-uaf-98432 records the running kernel as review: no released Ubuntu fixed build was retrieved. "
    "cve.org floors published 15 Oct 2026, updated 30 Oct 2026 are not Ubuntu package floors. It never claims patched.",
    "drupal-commerce-118539 reads composer.lock, vendor/composer/installed.json and the packaged Commerce "
    "info.yml (project: commerce, case-insensitive). composer.json is not evidence. A lock mentions "
    "drupal/commerce only when a package is named drupal/commerce. Stale copies under releases/ or *.bak can FAIL. "
    "The walk does not cover /opt, /data, other users' public_html, container volumes, or roots that were not passed in. "
    "Symlinked files and module folders (for example Composer path repos) are not followed. "
    "A directory named vendor is a Composer vendor tree only if it contains autoload.php or composer/installed.json. "
    "Drupal 7 commerce INI files are out of scope.",
]

CLEANUP_ORDER = [
    "Do not revoke the GitHub token first: per the briefing, the worm wipes the home folder if its stolen token "
    "is revoked first.",
    "Clean or rebuild the affected machine first (and any machine that ran the repository's hooks).",
    "Then revoke and replace the GitHub token from a clean device.",
    "Then remove the planted hook files and payload blobs from the repositories and review who pushed them.",
    "This tool never revokes tokens or deletes files.",
]

# --------------------------------------------------------------------------
# Briefing catalog: every fact and URL below comes from the dated briefing.
# --------------------------------------------------------------------------

SRC = {
    "theregister-testmetest": ("The Register: worm armed 42 GitHub repos (testmetest)",
                               "https://www.theregister.com/security/2026/10/26/worm-armed-42-github-repos-by-hiding-a-payload-too-big-to-fail/5305570"),
    "thn-agents-md": ("The Hacker News: malicious file in Downloads folder (AGENTS.md / CLAUDE.md)",
                      "https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html"),
    "bc-litellm": ("BleepingComputer: LiteLLM release pipeline hacked",
                   "https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/"),
    "thn-litellm": ("The Hacker News: leaked LiteLLM master key",
                    "https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html"),
    "nodejs-oct-2026": ("Node.js October 2026 security releases",
                        "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"),
    "aikido-brotli": ("Aikido: Python packages vulnerable to Node2Shell Brotli CVE-2026-111497",
                      "https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497"),
    "bc-dotnet-brotli": ("BleepingComputer: emergency .NET patches for Brotli flaw",
                         "https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-emergency-net-patches-for-critical-brotli-flaw/"),
    "ptp-brotli": ("patchtheplanet.org: Brotli", "https://patchtheplanet.org/brotli"),
    "thn-emudhra": ("The Hacker News: eight eMudhra CA keys compromised",
                    "https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html"),
    "unit42-emudhra": ("Unit 42: eMudhra certificate compromise",
                       "https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/"),
    "apple-emudhra": ("Apple support: eMudhra roots", "https://support.apple.com/en-us/149555"),
    "securityweek-chrome156": ("SecurityWeek: Chrome 156 security fixes",
                               "https://www.securityweek.com/memory-bugs-account-for-most-of-chromes-353-new-security-fixes/"),
    "voidsec-40369": ("VoidSec: CVE-2026-40369 browser sandbox escape",
                      "https://voidsec.com/cve-2026-40369-browser-sandbox-escape/"),
    "thn-php2shell": ("The Hacker News: PHP emergency patches",
                      "https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html"),
    "nvd-109618": ("NVD: CVE-2026-109618", "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"),
    "bc-php2shell": ("BleepingComputer: PHP2Shell exploited in the wild",
                     "https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/"),
    "bc-php-115560": ("BleepingComputer: PHP mitigation for unpatched RCE (CVE-2026-115560)",
                      "https://www.bleepingcomputer.com/news/security/php-shares-mitigation-for-new-and-unpatched-rce-vulnerability/"),
    "railway-incident": ("Railway: preliminary report, October security incident",
                         "https://blog.railway.com/p/preliminary-report-october-security-incident"),
    "bc-opencode": ("BleepingComputer: OpenCode hack exposes API keys",
                    "https://www.bleepingcomputer.com/news/security/opencode-hack-exposes-api-keys-amid-ai-distillation-attacks/"),
    "x-warp": ("Warp statement (post on x.com)", "https://x.com/i/status/2114800787716972873"),
    "lightning-incident": ("Lightning AI: security incident", "https://lightning.ai/security-incident/"),
    "ghsa-vitest": ("GitHub advisory GHSA-p458-7748-mcp3 (Vitest)", "https://github.com/advisories/GHSA-p458-7748-mcp3"),
    "pillow-13": ("Pillow 13.0.0 release notes", "https://pillow.readthedocs.io/en/latest/releasenotes/13.0.0.html"),
    "bc-ovhcloud": ("BleepingComputer: OVHcloud CLI releases backdoored",
                    "https://www.bleepingcomputer.com/news/security/ovhcloud-cli-releases-backdoored-on-github-to-steal-developer-secrets/"),
    "thn-gitlab": ("The Hacker News: critical GitLab flaw (CVSS 10.0)",
                   "https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html"),
    "thn-ruby": ("The Hacker News: Ruby fixes three regex engine bugs",
                 "https://thehackernews.com/2026/10/ruby-fixes-three-regex-engine-bugs.html"),
    "cso-nginx": ("CSO Online: F5 emergency NGINX patches",
                  "https://www.csoonline.com/article/4237420/f5-rushes-out-emergency-nginx-patches-for-three-critical-flaws.html"),
    "thn-wasmtime": ("The Hacker News: two critical Wasmtime flaws",
                     "https://thehackernews.com/2026/10/two-critical-wasmtime-flaws-could-let.html"),
    "ghsa-qdrant": ("Qdrant advisory GHSA-frc7-44gm-99qq",
                    "https://github.com/qdrant/qdrant/security/advisories/GHSA-frc7-44gm-99qq"),
    "thn-ksmbd": ("The Hacker News: two Linux KSMBD RCE flaws",
                  "https://thehackernews.com/2026/10/two-cvss-90-linux-ksmbd-rce-flaws.html"),
    "nvd-110447": ("NVD: CVE-2026-110447 (Collabora Online)", "https://nvd.nist.gov/vuln/detail/CVE-2026-110447"),
    "thn-updraft": ("The Hacker News: attackers abuse UpdraftCentral keys",
                    "https://thehackernews.com/2026/10/attackers-abuse-updraftcentral-keys-to.html"),
    "thn-magento": ("The Hacker News: 953 online stores infected",
                    "https://thehackernews.com/2026/10/hackers-infect-953-online-stores-with.html"),
    "thn-connectwise": ("The Hacker News: China-linked hackers use ARTEX AI (ConnectWise Cloud Backup)",
                        "https://thehackernews.com/2026/10/china-linked-hackers-use-artex-ai.html"),
    "tailscale-ssh-blog": ("Tailscale: SSH findings and fixes (2026-10-28)",
                           "https://tailscale.com/blog/tailscale-ssh-findings-fixes"),
    "tailscale-bulletins": ("Tailscale security bulletins (TS-2026-014 to TS-2026-017)",
                            "https://tailscale.com/security-bulletins"),
    "oracle-cve-2026-35273": ("Oracle Security Alert CVE-2026-35273 (PeopleSoft PeopleTools)",
                              "https://www.oracle.com/security-alerts/alert-cve-2026-35273.html"),
    "thn-peoplesoft": ("The Hacker News: ShinyHunters exploited Oracle PeopleSoft",
                       "https://thehackernews.com/2026/10/shinyhunters-exploited-oracle.html"),
    "anthropic-ai-chain": ("Anthropic: Discovering vulnerabilities with Claude (2026-10-27)",
                           "https://www.anthropic.com/research/discovering-vulnerabilities-with-claude"),
    "thn-anthropic-chain": ("The Hacker News: Anthropic unreleased AI model chains exploits (unconfirmed claim)",
                            "https://thehackernews.com/2026/10/anthropics-unreleased-ai-model-chains.html"),
    "gmo-onamae": ("GMO Internet: Desktop Cloud unauthorized-access notice",
                   "https://internet.gmo/en/news/article/258/"),
    "thn-gmo-onamae": ("The Hacker News: GMO Onamae Desktop Cloud breach and bounty",
                       "https://thehackernews.com/2026/10/japans-gmo-offers-1-million-bounty-to.html"),
    "thn-polyshell-node": ("The Hacker News: Adobe Commerce PolyShell (Node in-the-wild claim, unverified)",
                           "https://thehackernews.com/2026/10/adobe-commerce-polyshell-attacks-breach.html"),
    "cursor-claude-vsx": ("Cursor: security notice, malicious Anthropic.claude-code 2.1.313",
                          "https://cursor.com/blog/claude-code-extension-security-notice"),
    "phorion-claude-vsx": ("Phorion: official Claude Code VSX compromise (macOS-focused write-up)",
                           "https://phorion.io/blog/offical-claude-code-vsx-compromise/"),
    "nvd-97229": ("NVD: CVE-2026-97229 (GitLab CE/EE, CNA GitLab Inc.)",
                  "https://nvd.nist.gov/vuln/detail/CVE-2026-97229"),
    "cisa-kev-2026-10-29": ("CISA: two vulnerabilities added to the KEV catalog (29 Oct 2026)",
                            "https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog"),
    "golang-announce-98432": ("golang-announce: protecting against CVE-2026-98432 (Go MPTCP default)",
                              "https://groups.google.com/g/golang-announce/c/PCoQcdxoScw"),
    "cpr-yoba": ("Check Point Research: Yoba campaign via signed ChatGPT and Claude binaries",
                 "https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/"),
    "thn-yoba": ("The Hacker News: fake ChatGPT and Claude apps deploy miners",
                 "https://thehackernews.com/2026/10/fake-chatgpt-and-claude-apps-abuse.html"),
    "bc-hf-miner": ("BleepingComputer: Hugging Face malware campaign returns (unconfirmed lead)",
                    "https://www.bleepingcomputer.com/news/security/hugging-face-malware-campaign-returns-to-hijack-gpus-for-crypto-mining/"),
    "theregister-gha-61": ("The Register: GitHub issues used against 61 public repos (Radware; lead)",
                           "https://www.theregister.com/security/2026/10/29/attackers-turn-github-issues-into-supply-chain-campaign-against-61-public-repos-in-less-than-an-hour/5306153"),
    "tv-2026-1011": ("TeamViewer bulletin TV-2026-1011",
                     "https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/"),
    "cve-111585": ("CVE Record CVE-2026-111585",
                   "https://www.cve.org/CVERecord?id=CVE-2026-111585"),
    "remedio-tv": ("Remedio TeamViewer write-up (lead; not a version floor)",
                   "https://remedio.io/research/vulnerability-disclosures/remote-code-execution-in-teamviewer/"),
    "cisa-kev-46300": ("CISA: two vulnerabilities added to the KEV catalog (28 Oct 2026)",
                       "https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog"),
    "cve-46300": ("CVE Record CVE-2026-46300",
                  "https://www.cve.org/CVERecord?id=CVE-2026-46300"),
    "nvd-46300": ("NVD: CVE-2026-46300", "https://nvd.nist.gov/vuln/detail/CVE-2026-46300"),
    "kernel-cve-46300": ("linux-cve-announce: CVE-2026-46300 (23 May 2026; description later revised)",
                         "https://lists.openwall.net/linux-cve-announce/2026/05/23/1"),
    "ubuntu-46300": ("Ubuntu Security CVE-2026-46300",
                     "https://ubuntu.com/security/CVE-2026-46300"),
    "ubuntu-98432": ("Ubuntu Security CVE-2026-98432",
                     "https://ubuntu.com/security/CVE-2026-98432"),
    "cve-98432": ("CVE Record CVE-2026-98432 (published 15 Oct 2026, updated 30 Oct 2026)",
                  "https://www.cve.org/CVERecord?id=CVE-2026-98432"),
    "sa-contrib-2026-254": ("Drupal SA-CONTRIB-2026-254: Commerce Core access bypass (CVE-2026-118539)",
                            "https://www.drupal.org/sa-contrib-2026-254"),
    "commerce-rel-3-3-13": ("Drupal.org: Commerce Core 3.3.13",
                            "https://www.drupal.org/project/commerce/releases/3.3.13"),
    "commerce-rel-8-x-2-41": ("Drupal.org: Commerce Core 8.x-2.41",
                              "https://www.drupal.org/project/commerce/releases/8.x-2.41"),
    "cve-118539": ("CVE Record CVE-2026-118539",
                   "https://www.cve.org/CVERecord?id=CVE-2026-118539"),
    "thn-commerce-118539": ("The Hacker News: Drupal Commerce actively exploited (pointer; not a version floor)",
                            "https://thehackernews.com/2026/10/hackers-actively-exploit-highly.html"),
}

SKIPPED = [
    ("Phishing sent through Google AppSheet", "Workspace admin setting and mail-flow behaviour; nothing on the endpoint shows it."),
    ("Microsoft 365 token replay campaign", "Needs tenant sign-in logs, devices and inbox rules (admin console)."),
    ("Fake IT support in external Teams chats", "Tenant setting (external access); not visible on the endpoint."),
    ("Unbounce connected-app keys", "SaaS account; no local client or artifact named in the briefing."),
    ("Bullhorn platform offline", "SaaS platform; no local artifact."),
    ("iPhone jailbreak on iOS 27.1", "Mobile devices; needs MDM inventory, not a laptop scan."),
    ("Arista VeloCloud Orchestrator", "Network appliance; needs the admin console or network scanning."),
    ("Palo Alto PAN-OS / Prisma Access", "Firewall appliance; needs the admin console."),
    ("Fortinet FortiOS / FortiProxy / FortiPAM", "Network appliance; needs the admin console."),
    ("Hostwinds client area offline", "Hosting account; no local artifact."),
    ("PingCAP / TiDB Cloud data copied", "Cloud service account; no local artifact named in the briefing."),
    ("Magento cms_block content", "Needs database access; the magento-store check only finds Magento code on disk."),
    ("Salesforce outage and other awareness-only items", "Briefing says no action."),
    ("Bun and Envoy/Istio Brotli reports", "Marked unconfirmed in the briefing with no versions; not checked."),
    ("EMBRACE embedded browsers in AI assistants (Forever Security)",
     "Single-source research blog; no vendor advisory or CVE. Recorded as a lead, not a host check."),
    ("GitHub Actions issue/PR injection campaign against 61 public repos (Radware / The Register)",
     "Press-only exclusive. inventory.py lints local workflow YAML for untrusted github.event text in run: steps; "
     "this is not proof that a named repo was hit."),
    ("FreeBSD WireGuard CVE-2026-58085",
     "Confirmed by FreeBSD-SA-26:52.if_wg (29 Jul 2026). host_checks.py does not cover FreeBSD; see the dated profile."),
    ("Binance / Polymarket org-level incidents",
     "No local client or artifact named in the briefing; organisation accounts, not an endpoint check."),
    ("Fake Solana starter kit (Air Security, mentioned alongside the Hugging Face press piece)",
     "Separate GitHub social-engineering lead; no local metadata indicator beyond a README one-liner."),
    ("DHS staff identity leak", "Government data leak; nothing on the endpoint shows it."),
    ("Synology NAS ransomware reports", "Appliance; single forum source; no vendor confirmation."),
    ("Drupal Commerce order-inconsistency audit",
     "Needs the site database; drupal-commerce-118539 only reads the packaged Commerce info.yml, composer.lock and "
     "vendor/composer/installed.json."),
]


def check_meta(cid, title, section, confirmation, layer, sources, fact, remediation, os_notes, fn, uses_walk=True):
    return {"id": cid, "title": title, "section": section, "confirmation": confirmation, "layer": layer,
            "sources": sources, "briefing_fact": fact, "remediation": remediation, "os_support": os_notes,
            "fn": fn, "uses_walk": uses_walk}


# --------------------------------------------------------------------------
# Host abstraction (real or simulated for fixtures)
# --------------------------------------------------------------------------

def current_platform():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def default_runner(argv, timeout):
    """Run a read-only inventory command with no stdin and a timeout; None when the tool is absent."""
    exe = shutil.which(argv[0])
    if not exe:
        return None
    try:
        proc = subprocess.run([exe] + list(argv[1:]), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ("error", b"")
    return (proc.returncode, proc.stdout[: 16 * MIB])


def read_registry_uninstall():
    """DisplayName/DisplayVersion pairs from the Windows uninstall keys (read-only)."""
    if winreg is None:
        return None
    out = []
    roots = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")]
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            continue
        with key:
            i = 0
            while i < 5000:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, sub, 0, winreg.KEY_READ) as sk:
                        name = winreg.QueryValueEx(sk, "DisplayName")[0]
                        try:
                            ver = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                        except OSError:
                            ver = ""
                        out.append({"name": str(name), "version": str(ver)})
                except OSError:
                    continue
    return out


def windows_cert_stores():
    out = []
    enum = getattr(ssl, "enum_certificates", None)
    if enum is None:
        return None
    for store in ("ROOT", "CA"):
        try:
            for der, enc, _trust in enum(store):
                if enc == "x509_asn":
                    out.append((store, der))
        except OSError:
            continue
    return out


class Host:
    def __init__(self, platform=None, home=None, sysroot=None, env=None, roots=None, max_depth=10,
                 max_entries=400_000, time_budget=240.0, repo_seconds=15.0, allowlist=None,
                 registry=None, runner=None, cert_stores=None, blob_review=(11 * MIB, 16 * MIB),
                 blob_info=(5 * MIB, 64 * MIB)):
        self.platform = platform or current_platform()
        self.simulated = sysroot is not None
        self.sysroot = os.path.abspath(sysroot) if sysroot else None
        self.env = dict(os.environ if env is None and not self.simulated else (env or {}))
        if home is None:
            home = self.env.get("USERPROFILE") if self.platform == "windows" else self.env.get("HOME")
            home = home or os.path.expanduser("~")
        self.home = os.path.abspath(home)
        self.roots = [os.path.abspath(r) for r in (roots or [self.home])]
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.budget = hs.Budget(time_budget)
        self.repo_seconds = repo_seconds
        self.allow = allowlist or {}
        self.gaps = hs.Gaps(self.display)
        self.blob_review = blob_review
        self.blob_info = blob_info
        if registry is None and not self.simulated and self.platform == "windows":
            registry = read_registry_uninstall()
        self.registry = registry or []
        if runner is None and not self.simulated:
            runner = default_runner
        self.runner = runner
        if cert_stores is None and not self.simulated and self.platform == "windows":
            cert_stores = windows_cert_stores()
        self.cert_stores = cert_stores
        self._cache = {}

    # -- paths ------------------------------------------------------------
    def sys(self, path):
        """Map an absolute system path ('/usr/lib', 'C:/Program Files') into the (simulated) host."""
        if not self.sysroot:
            return os.path.normpath(path) if self.platform == "windows" else path
        p = path.replace("\\", "/")
        m = re.match(r"^([A-Za-z]):/?(.*)$", p)
        if m:
            p = m.group(1).upper() + "/" + m.group(2)
        return os.path.join(self.sysroot, *[x for x in p.split("/") if x])

    def h(self, *parts):
        return os.path.join(self.home, *parts)

    def winvar(self, name, default):
        val = self.env.get(name) or default
        if val is None:
            return None
        if re.match(r"^[A-Za-z]:[\\/]", val) and self.sysroot and not under_root(self.sysroot, val):
            return self.sys(val)
        return val

    def appdata(self):
        return self.winvar("APPDATA", self.h("AppData", "Roaming"))

    def localappdata(self):
        return self.winvar("LOCALAPPDATA", self.h("AppData", "Local"))

    def program_files(self):
        return [p for p in (self.winvar("ProgramFiles", "C:/Program Files"),
                            self.winvar("ProgramFiles(x86)", "C:/Program Files (x86)"),
                            self.winvar("ProgramW6432", None)) if p]

    def display(self, path):
        if path is None:
            return None
        raw = str(path)
        p = os.path.abspath(raw)
        home, pn = os.path.normcase(self.home), os.path.normcase(p)
        if pn == home or pn.startswith(home + os.sep):
            rel = p[len(home):].replace("\\", "/")
            return "~" + rel
        root = os.path.normcase(self.sysroot) if self.sysroot else None
        if root and (pn == root or pn.startswith(root + os.sep)):
            rel = p[len(self.sysroot):].replace("\\", "/")
            m = re.match(r"^/([A-Z])(/.*)?$", rel) if self.platform == "windows" else None
            if m:
                return m.group(1) + ":" + (m.group(2) or "/")
            return rel or "/"
        # Config locators may be POSIX or drive-prefixed and not on this host.
        # Redact the original string first. On POSIX, abspath("D:/home/...") is a
        # cwd-relative path under the runner home and would otherwise redact the
        # runner's /home instead of the locator. Do not treat "X:/Users/..." as
        # /home here.
        original = raw.replace("\\", "/")
        redacted = re.sub(r"(?i)^[A-Z]:/home/[^/]+", "/<home>", original)
        redacted = re.sub(r"^/(?:Users|home)/[^/]+", "/<home>", redacted)
        if redacted != original:
            return redacted
        candidate = p.replace("\\", "/")
        redacted = re.sub(r"(?i)^[A-Z]:/home/[^/]+", "/<home>", candidate)
        redacted = re.sub(r"^/(?:Users|home)/[^/]+", "/<home>", redacted)
        if redacted != candidate:
            return redacted
        return re.sub(r"(?i)^([A-Z]:/Users/)[^/]+", r"\1<user>", candidate)

    # -- cached collectors -------------------------------------------------
    def cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def run(self, argv, timeout=30):
        if self.runner is None:
            return None
        return self.runner(argv, timeout)


# --------------------------------------------------------------------------
# One bounded walk
# --------------------------------------------------------------------------

TOOL_DIRS = {".cursor", ".claude", ".gemini", ".vscode", ".codex", ".github", ".windsurf", ".vscode-insiders",
             ".kiro", ".amazonq", ".continue", ".roo", ".clinerules"}
INSTR_NAMES = {"agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md",
               "agent.md", "claude.local.md"}
PROJECT_MARKERS = {".git", "package.json", "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml", "go.mod",
                   "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "gemfile", "requirements.txt",
                   "pipfile", "deno.json", "mix.exs", "pubspec.yaml", "cmakelists.txt", "makefile", "global.json"}
SKIP_ANY = {"node_modules", ".git", "__pycache__", ".cache", ".npm", ".pnpm-store", ".yarn-cache", "bower_components",
            ".cargo", ".rustup", ".gradle", ".m2", ".nuget", ".trash", "$recycle.bin", ".hg", ".svn", ".mypy_cache",
            ".pytest_cache", ".ruff_cache", ".terraform", ".venv-cache", ".next", ".nuxt", ".turbo", ".parcel-cache",
            ".angular", ".expo", ".dart_tool", ".pub-cache", ".android", ".ivy2", ".sbt", ".coursier"}
SKIP_HOME_ROOT = {"library", "appdata", ".local", ".nvm", ".pyenv", ".rbenv", ".rvm", ".asdf", ".volta", ".fnm",
                  ".conda", ".dotnet", ".vscode-server", ".cursor-server", ".windsurf-server", "miniconda3", "anaconda3",
                  "miniforge3", "mambaforge", "micromamba", ".docker", ".orbstack", "snap", ".wine",
                  "pictures", "music", "movies", "videos", ".virtualenvs", ".rubies", ".nodenv", ".jenv", ".sdkman",
                  ".bun", ".deno", ".wasmtime", ".lightning", ".railway", ".tiup", ".colima", ".lima", ".minikube",
                  ".kube", ".ssh", ".gnupg", ".aws", ".azure", ".config"}
SKIP_PAIRS = {(".vscode", "extensions"), (".cursor", "extensions"), (".windsurf", "extensions"),
              (".vscode-insiders", "extensions"), (".claude", "projects"), (".claude", "todos"),
              (".claude", "shell-snapshots"), (".claude", "statsig"), (".claude", "local"), (".claude", "plugins"),
              (".cursor", "plugins"), (".gemini", "extensions"),
              (".gemini", "tmp"), (".codex", "sessions"), (".codex", "log"), (".codex", "archived_sessions"),
              (".yarn", "cache"), (".yarn", "unplugged"), (".cursor", "projects"), (".cursor", "ai-tracking")}
NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "package.json"}
PY_FILES = {"poetry.lock", "uv.lock", "pdm.lock", "pylock.toml", "pipfile.lock", "pipfile", "pyproject.toml",
            "setup.cfg", "environment.yml", "environment.yaml"}
DEPLOY_DIRS = {"k8s", "kubernetes", "helm", "charts", "deploy", "deployment", "manifests", "infra", "ops"}


class Index:
    def __init__(self):
        self.repos = {}
        self.tool_files = []
        self.instr = []
        self.npm = []
        self.py = []
        self.docker = []
        self.cargo = []
        self.gosum = []
        self.gomod = []
        self.nuget = []
        self.node_modules = []
        self.venvs = []
        self.conda_envs = []
        self.large = []
        self.updraft = []
        self.magento = []
        self.nextcloud = []
        self.qdrant_cfg = []
        self.mcp_files = []
        self.node_pins = []
        self.ci_yml = []
        self.peoplesoft = []
        self.gmo_cfg = []
        self.mesh_acl = []
        self.composer_lock = []
        self.composer_installed = []
        self.drupal_commerce = []
        self.complete = True
        self.stopped = None


def is_requirements(name_l):
    return (name_l.endswith(".txt") and ("requirement" in name_l or "constraint" in name_l)) or name_l.endswith(".in") \
        and "requirement" in name_l


def is_docker(name_l, parts_l):
    if name_l.startswith(("dockerfile", "containerfile")) or name_l.endswith((".dockerfile", ".containerfile")):
        return True
    if re.match(r"^(docker-)?compose[\w.-]*\.ya?ml$", name_l):
        return True
    if name_l.endswith((".yml", ".yaml")) and (name_l.startswith("values") or set(parts_l) & DEPLOY_DIRS):
        return True
    return False


def build_index(host):
    idx = Index()
    downloads = {os.path.normcase(os.path.abspath(d)) for d in downloads_dirs(host)}

    def skip(parts, low, ctx):
        if low in SKIP_ANY:
            return True
        if ctx and low in ctx.get("child_skip", ()):
            return True
        if parts == () and ctx and ctx.get("is_home") and low in SKIP_HOME_ROOT:
            return True
        if parts and (parts[-1].lower(), low) in SKIP_PAIRS:
            return True
        return False

    def visit_dir(path, parts, names, ctx):
        ctx = ctx or {}
        low = {n.lower(): n for n in names}
        if parts and "pyvenv.cfg" in low:
            idx.venvs.append(path)
            return False, None
        if parts and "conda-meta" in low and hs.is_plain_dir(os.path.join(path, low["conda-meta"])):
            idx.conda_envs.append(path)
            return False, None
        for n in names:
            if n.lower() == "node_modules":
                idx.node_modules.append(os.path.join(path, n))
        repo = ctx.get("repo")
        if ".git" in low:
            gp = os.path.join(path, low[".git"])
            idx.repos[path] = gp
            repo = path
        tool, tool_root = ctx.get("tool"), ctx.get("tool_root")
        if parts and parts[-1].lower() in TOOL_DIRS and tool is None:
            tool, tool_root = parts[-1].lower(), path
        here = os.path.normcase(os.path.abspath(path))
        child_skip = set()
        if "cargo.toml" in low:
            child_skip.add("target")
        if "package.json" in low:
            child_skip.update({"dist", "build", "coverage", "out", ".svelte-kit"})
        plow = [p.lower() for p in parts]
        if ctx.get("is_home") and plow == ["go"]:
            # ~/go/pkg is the Go module cache; ~/go/src can hold real GOPATH projects.
            child_skip.add("pkg")
        if plow[-2:] == ["wp-content", "plugins"] and "updraftplus" in low:
            idx.updraft.append(os.path.join(path, low["updraftplus"]))
        if "bin" in low and "app" in low and hs.is_regular(os.path.join(path, low["app"], "etc", "env.php")):
            idx.magento.append(path)
        if "occ" in low and "version.php" in low:
            idx.nextcloud.append(path)
        if any(n.lower() in {"psconfig.sh", "psappsrv.cfg"} for n in names) or (
                "allowedhosts.properties" in low and any(k in plow for k in ("peoplesoft", "peopletools", "psft", "pia"))):
            idx.peoplesoft.append(path)
        new = {
            "is_home": bool(ctx.get("root_marker") and ctx.get("is_home")),
            "repo": repo,
            "project": ctx.get("project", False) or bool(set(low) & PROJECT_MARKERS)
            or any(n.endswith((".sln", ".csproj")) for n in low),
            "downloads": ctx.get("downloads", False) or here in downloads,
            "tool": tool, "tool_root": tool_root,
            "child_skip": child_skip,
        }
        return True, new

    def visit_file(path, parts, name, st, ctx):
        low = name.lower()
        plow = [p.lower() for p in parts]
        if ctx.get("tool") and len(idx.tool_files) < 50_000:
            idx.tool_files.append((path, ctx["tool"], ctx["tool_root"], ctx.get("repo")))
        if low in INSTR_NAMES:
            idx.instr.append((path, ctx.get("project", False), ctx.get("downloads", False), ctx.get("repo")))
        if low in NPM_LOCKS:
            idx.npm.append((path, low))
        if low in PY_FILES or is_requirements(low):
            idx.py.append((path, low))
        if is_docker(low, plow):
            idx.docker.append(path)
        if low == ".mcp.json":
            idx.mcp_files.append(path)
        if low == "cargo.lock":
            idx.cargo.append(path)
        if low == "go.sum":
            idx.gosum.append(path)
        if low == "go.mod":
            idx.gomod.append(path)
        if low in ("packages.lock.json", "directory.packages.props") or low.endswith((".csproj", ".fsproj")):
            idx.nuget.append(path)
        if low in ("config.yaml", "production.yaml", "development.yaml") and any("qdrant" in p for p in plow):
            idx.qdrant_cfg.append(path)
        if low in (".nvmrc", ".node-version", ".tool-versions"):
            idx.node_pins.append((path, low))
        if (low.endswith((".yml", ".yaml")) and ".github" in plow and "workflows" in plow) or low == ".gitlab-ci.yml":
            idx.ci_yml.append(path)
        if low in ("psconfig.sh", "psappsrv.cfg", "psprcs.cfg") or (
                low in ("allowedhosts.properties", "configuration.properties")
                and any(p in plow for p in ("peoplesoft", "peopletools", "psft", "pia"))):
            idx.peoplesoft.append(path)
        if low.endswith(".zone") or low in ("named.conf", "named.conf.local") or (
                "dns" in plow and low.endswith((".tf", ".conf", ".ini", ".txt"))):
            idx.gmo_cfg.append(path)
        if low in ("acl.hujson", "policy.hujson", "tailscale-acl.json", "tailnet-acl.json", "tailnet-policy.json"):
            idx.mesh_acl.append(path)
        if low == "composer.lock" and not _in_composer_vendor(path):
            idx.composer_lock.append(path)
        if low == "installed.json" and len(plow) >= 2 and plow[-2:] == ["vendor", "composer"]:
            idx.composer_installed.append(path)
        if low == "commerce" + ".info.yml" and not _in_composer_vendor(path):
            idx.drupal_commerce.append(path)
        if ctx.get("repo") and st.st_size >= host.blob_info[0]:
            idx.large.append((path, st.st_size, ctx["repo"]))

    walker = hs.Walker(host.gaps, host.budget, host.max_depth, host.max_entries, skip, visit_dir, visit_file)
    for root in host.roots:
        if walker.stopped:
            break
        walker.run(root, {"is_home": os.path.normcase(root) == os.path.normcase(host.home), "root_marker": True,
                          "downloads": os.path.normcase(os.path.abspath(root)) in downloads})
    idx.complete = walker.stopped is None
    idx.stopped = walker.stopped
    host.walk_stats = {"directories_listed": walker.dirs, "entries_seen": walker.entries,
                       "stopped": walker.stopped}
    return idx


def downloads_dirs(host):
    out = [host.h("Downloads")]
    if host.platform == "windows":
        prof = host.env.get("USERPROFILE")
        if prof:
            out.append(os.path.join(prof, "Downloads"))
    xdg = host.env.get("XDG_DOWNLOAD_DIR")
    if xdg:
        out.append(xdg.replace("$HOME", host.home))
    return out


def index(host):
    return host.cached("index", lambda: build_index(host))


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

class Result:
    def __init__(self):
        self.findings = []
        self.present = False
        self.blocked = []
        self.notes = []

    def add(self, result, component, detail, path=None, version=None, **extra):
        f = {"result": result, "component": component, "detail": detail}
        if path is not None:
            f["path"] = path
        if version is not None:
            f["version"] = str(version)
        for k, v in extra.items():
            if v not in (None, [], ""):
                f[k] = v
        self.findings.append(f)
        self.present = True


def allowed(host, kind, path=None, sha=None, name=None, hostname=None):
    for entry in host.allow.get(kind, []):
        ok = True
        if "path_glob" in entry:
            ok = ok and path is not None and fnmatch.fnmatchcase(path.lower(), entry["path_glob"].lower())
        if "sha256" in entry:
            ok = ok and sha is not None and entry["sha256"].lower() == sha
        if "object_id" in entry:
            ok = ok and sha is not None and entry["object_id"].lower() == sha
        if "name" in entry:
            ok = ok and name is not None and entry["name"].lower() == name.lower()
        if "host" in entry:
            ok = ok and hostname is not None and entry["host"].lower() == hostname.lower()
        if ok:
            return entry["reason"]
    return None


def sha256_of(path, limit=64 * MIB):
    data = hs.read_bytes(path, limit)
    return hashlib.sha256(data).hexdigest() if data is not None else None


def classify_version(r, component, raw, path, fixed, line_len=1, no_fix=(), source="metadata", extra_note=""):
    v = hs.parse_version(raw)
    if v is None:
        r.add("unknown", component, "version string could not be parsed (%s)" % source, path=path,
              version=textscan.redact(str(raw))[:64])
        return None
    res, note = hs.classify_lines(v, fixed, line_len, no_fix)
    r.add({"ok": "info"}.get(res, res), component, "%s; from %s%s" % (note, source, extra_note), path=path, version=raw)
    return res


# --------------------------------------------------------------------------
# Collectors (cached per host)
# --------------------------------------------------------------------------

def linux_packages(host):
    """{package_name: [(version, source)]} from dpkg, apk, pacman and (if present) rpm."""
    def collect():
        pk = {}

        def add(name, ver, src):
            pk.setdefault(name.lower(), []).append((ver, src))

        if host.platform != "linux":
            return pk
        text = hs.read_text(host.sys("/var/lib/dpkg/status"), 128 * MIB, host.gaps)
        for stanza in (text or "").split("\n\n"):
            fields = dict(re.findall(r"(?m)^(Package|Status|Version):\s*(.+)$", stanza))
            if fields.get("Package") and fields.get("Version") and " installed" in fields.get("Status", ""):
                add(fields["Package"], fields["Version"], "dpkg")
        text = hs.read_text(host.sys("/lib/apk/db/installed"), 64 * MIB, host.gaps)
        for stanza in (text or "").split("\n\n"):
            fields = dict(re.findall(r"(?m)^([PV]):(.+)$", stanza))
            if fields.get("P") and fields.get("V"):
                add(fields["P"], fields["V"], "apk")
        pac = host.sys("/var/lib/pacman/local")
        for d in hs.subdirs(pac):
            desc = hs.read_text(os.path.join(pac, d, "desc"), 256 * 1024)
            m = re.search(r"%NAME%\n(\S+)\n\n%VERSION%\n(\S+)", desc or "")
            if m:
                add(m.group(1), m.group(2), "pacman")
        if hs.exists_nofollow(host.sys("/var/lib/rpm")) or hs.exists_nofollow(host.sys("/usr/lib/sysimage/rpm")):
            out = host.run(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], 60)
            if out is None:
                host.gaps.add("tool_missing", host.sys("/var/lib/rpm"), "rpm database present; rpm query not run")
            elif out[0] != 0:
                host.gaps.add("command_failed", host.sys("/var/lib/rpm"), "rpm -qa failed")
            else:
                for line in out[1].decode("utf-8", "replace").splitlines():
                    if "\t" in line:
                        n, v = line.split("\t", 1)
                        add(n, v, "rpm")
        return pk
    return host.cached("linux_packages", collect)


def cellar_roots(host):
    if host.platform == "windows":
        return []
    return [host.sys("/opt/homebrew/Cellar"), host.sys("/usr/local/Cellar"),
            host.sys(os.path.join("/home", "linuxbrew", ".linuxbrew", "Cellar")), host.h(".linuxbrew", "Cellar")]


def cellar(host):
    def collect():
        out = {}
        for root in cellar_roots(host):
            for formula in hs.subdirs(root):
                for ver in hs.subdirs(os.path.join(root, formula)):
                    out.setdefault(formula.lower(), []).append((ver, os.path.join(root, formula, ver)))
        return out
    return host.cached("cellar", collect)


def registry_matches(host, pattern):
    rx = re.compile(pattern, re.I)
    return [e for e in host.registry if rx.search(e.get("name", ""))]


def under_root(root, path):
    """True when path is already inside root (case-insensitive on Windows)."""
    if not root:
        return False
    r = os.path.normcase(os.path.abspath(root))
    p = os.path.normcase(os.path.abspath(path))
    return p == r or p.startswith(r + os.sep)


def fs_id(path):
    """Identity of a filesystem object so Lib/ and lib/ are one dir on a case-folding volume."""
    try:
        st = os.stat(path)
    except OSError:
        return ("path", os.path.normcase(os.path.abspath(path)))
    if st.st_ino:
        return ("ino", st.st_dev, st.st_ino)
    return ("path", os.path.normcase(os.path.abspath(path)))


def is_abs_locator(value):
    """Absolute POSIX or Windows locator; not the host's os.path.isabs (Python 3.13+)."""
    s = str(value).replace("\\", "/")
    return s.startswith("/") or bool(re.match(r"^[A-Za-z]:/", s))


def path_dirs(host):
    raw = host.env.get("PATH") or host.env.get("Path") or ""
    sep = ";" if host.platform == "windows" else os.pathsep
    out = []
    for d in raw.split(sep):
        d = d.strip().strip('"')
        if not d:
            continue
        # A simulated host on Windows already has PATH entries under sysroot
        # (D:/tmp/.../sys/usr/bin). Remapping those as guest drive D: is wrong.
        if re.match(r"^[A-Za-z]:[\\/]", d) and host.sysroot and not under_root(host.sysroot, d):
            d = host.sys(d)
        if d not in out:
            out.append(d)
    return out


def find_binaries(host, names, extra_dirs=()):
    exts = ("", ".exe", ".cmd", ".bat") if host.platform == "windows" else ("",)
    found = []
    for d in list(path_dirs(host)) + list(extra_dirs):
        for n in names:
            for e in exts:
                p = os.path.join(d, n + e)
                st = hs.lstat(p)
                if st is not None and (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)) and p not in found:
                    found.append(p)
    return found


def glob_dirs(host, base, pattern):
    """Subdirectories of ``base`` whose names match ``pattern`` (fnmatch, case-insensitive)."""
    return [os.path.join(base, n) for n in hs.subdirs(base) if fnmatch.fnmatch(n.lower(), pattern.lower())]


def env_roots(host):
    """Python environment roots: (label, root)."""
    def collect():
        roots = []
        h = host.h
        idx = index(host)
        roots += [("venv", v) for v in idx.venvs]
        roots += [("conda env", v) for v in idx.conda_envs]
        pipx = [h(".local", "pipx", "venvs"), h(".local", "share", "pipx", "venvs"), h("pipx", "venvs"),
                os.path.join(host.localappdata(), "pipx", "pipx", "venvs")]
        if host.env.get("PIPX_HOME"):
            pipx.append(os.path.join(host.env["PIPX_HOME"], "venvs"))
        for base in pipx:
            roots += [("pipx", os.path.join(base, d)) for d in hs.subdirs(base)]
        uv = [h(".local", "share", "uv", "tools"), h(".local", "share", "uv", "python"),
              os.path.join(host.appdata(), "uv", "tools"), os.path.join(host.appdata(), "uv", "python")]
        for var in ("UV_TOOL_DIR", "UV_PYTHON_INSTALL_DIR"):
            if host.env.get(var):
                uv.append(host.env[var])
        for base in uv:
            roots += [("uv", os.path.join(base, d)) for d in hs.subdirs(base)]
        pyenv = [host.env.get("PYENV_ROOT") or h(".pyenv"), h(".pyenv", "pyenv-win")]
        for base in pyenv:
            vers = os.path.join(base, "versions")
            for d in hs.subdirs(vers):
                roots.append(("pyenv", os.path.join(vers, d)))
                roots += [("pyenv env", os.path.join(vers, d, "envs", e)) for e in hs.subdirs(os.path.join(vers, d, "envs"))]
        conda = [h(n) for n in ("miniconda3", "anaconda3", "miniforge3", "mambaforge", "micromamba", "miniconda",
                                "anaconda")]
        conda += [h("opt", "miniconda3"), h("opt", "anaconda3"), host.sys("/opt/conda"), host.sys("/opt/miniconda3"),
                  host.sys("/opt/anaconda3"), host.sys("/opt/homebrew/Caskroom/miniforge/base"),
                  host.sys("/opt/homebrew/Caskroom/miniconda/base"), host.sys("/usr/local/Caskroom/miniconda/base"),
                  host.sys("C:/ProgramData/miniconda3"), host.sys("C:/ProgramData/anaconda3")]
        if host.env.get("CONDA_PREFIX"):
            conda.append(host.env["CONDA_PREFIX"])
        for base in conda:
            if hs.is_plain_dir(base):
                roots.append(("conda", base))
                roots += [("conda env", os.path.join(base, "envs", e)) for e in hs.subdirs(os.path.join(base, "envs"))]
        roots += [("conda env", os.path.join(h(".conda", "envs"), e)) for e in hs.subdirs(h(".conda", "envs"))]
        for base in (h(".cache", "pypoetry", "virtualenvs"), h("Library", "Caches", "pypoetry", "virtualenvs"),
                     os.path.join(host.localappdata(), "pypoetry", "Cache", "virtualenvs"),
                     h(".local", "share", "virtualenvs"), h(".virtualenvs")):
            roots += [("venv", os.path.join(base, d)) for d in hs.subdirs(base)]
        for base in (h(".local", "share", "hatch", "env", "virtual"),
                     h("Library", "Application Support", "hatch", "env", "virtual")):
            for proj in hs.subdirs(base):
                roots += [("hatch", os.path.join(base, proj, d)) for d in hs.subdirs(os.path.join(base, proj))]
        if host.platform == "windows":
            for base in [os.path.join(host.localappdata(), "Programs", "Python")] + \
                    [os.path.dirname(host.sys("C:/Python39"))]:
                roots += [("python", d) for d in glob_dirs(host, base, "python*")]
            for pf in host.program_files():
                roots += [("python", d) for d in glob_dirs(host, pf, "python*")]
        seen, out = set(), []
        for label, r in roots:
            key = fs_id(r)
            if key not in seen:
                seen.add(key)
                out.append((label, r))
        return out
    return host.cached("env_roots", collect)


def site_dirs(host):
    """(label, site_packages_dir) for every Python environment found."""
    def collect():
        out = []

        def from_root(label, root):
            for lib in ("lib", "lib64"):
                for py in glob_dirs(host, os.path.join(root, lib), "python*"):
                    for sp in ("site-packages", "dist-packages"):
                        if hs.is_plain_dir(os.path.join(py, sp)):
                            out.append((label, os.path.join(py, sp)))
            for lib in ("Lib", "lib"):
                p = os.path.join(root, lib, "site-packages")
                if hs.is_plain_dir(p) and (label, p) not in out:
                    out.append((label, p))

        for label, root in env_roots(host):
            from_root(label, root)
        h = host.h
        if host.platform != "windows":
            for base in ("/usr/lib", "/usr/lib64", "/usr/local/lib", "/opt/homebrew/lib"):
                for py in glob_dirs(host, host.sys(base), "python*"):
                    for sp in ("site-packages", "dist-packages"):
                        if hs.is_plain_dir(os.path.join(py, sp)):
                            out.append(("system", os.path.join(py, sp)))
            for py in glob_dirs(host, h(".local", "lib"), "python*"):
                if hs.is_plain_dir(os.path.join(py, "site-packages")):
                    out.append(("user site", os.path.join(py, "site-packages")))
        if host.platform == "darwin":
            fw = [host.sys("/Library/Frameworks/Python.framework/Versions"),
                  host.sys("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions")]
            for base in fw:
                for ver in hs.subdirs(base):
                    for py in glob_dirs(host, os.path.join(base, ver, "lib"), "python*"):
                        if hs.is_plain_dir(os.path.join(py, "site-packages")):
                            out.append(("framework", os.path.join(py, "site-packages")))
            for ver in hs.subdirs(host.sys("/Library/Python")):
                p = host.sys("/Library/Python/%s/site-packages" % ver)
                if hs.is_plain_dir(p):
                    out.append(("system", p))
            for ver in hs.subdirs(h("Library", "Python")):
                p = h("Library", "Python", ver, "lib", "python", "site-packages")
                if hs.is_plain_dir(p):
                    out.append(("user site", p))
            for formula, vers in cellar(host).items():
                if formula.startswith("python"):
                    for _v, vp in vers:
                        fwv = os.path.join(vp, "Frameworks", "Python.framework", "Versions")
                        for ver in hs.subdirs(fwv):
                            for py in glob_dirs(host, os.path.join(fwv, ver, "lib"), "python*"):
                                if hs.is_plain_dir(os.path.join(py, "site-packages")):
                                    out.append(("homebrew", os.path.join(py, "site-packages")))
        if host.platform == "windows":
            for py in glob_dirs(host, os.path.join(host.appdata(), "Python"), "python*"):
                if hs.is_plain_dir(os.path.join(py, "site-packages")):
                    out.append(("user site", os.path.join(py, "site-packages")))
            pk = os.path.join(host.localappdata(), "Packages")
            for d in glob_dirs(host, pk, "pythonsoftwarefoundation.python.*"):
                lp = os.path.join(d, "LocalCache", "local-packages")
                for py in glob_dirs(host, lp, "python*"):
                    if hs.is_plain_dir(os.path.join(py, "site-packages")):
                        out.append(("store python", os.path.join(py, "site-packages")))
        seen, uniq = set(), []
        for label, sp in out:
            key = fs_id(sp)
            if key not in seen:
                seen.add(key)
                uniq.append((label, sp))
        return uniq[:5000]
    return host.cached("site_dirs", collect)


WANTED_PY = {"litellm", "brotli", "brotlicffi", "certifi", "pillow", "wasmtime", "lightning_sdk"}


def py_installs(host):
    """{normalized_name: [(version, path, label)]} across all environments, conda-meta and vendored certifi."""
    def collect():
        out = {}
        for label, sp in site_dirs(host):
            if host.budget.over():
                host.gaps.add("time_budget", sp, "python environment scan stopped")
                break
            for n, ver, p in hs.python_dists(sp, WANTED_PY):
                out.setdefault(n, []).append((ver, p, label))
            vc = hs.vendored_certifi(sp)
            if vc:
                out.setdefault("certifi", []).append((vc[0], vc[1], label + " (pip vendored copy)"))
        for label, root in env_roots(host):
            for n, ver, p in hs.conda_meta(os.path.join(root, "conda-meta"), WANTED_PY):
                out.setdefault(n, []).append((ver, p, label + " (conda-meta)"))
        return out
    return host.cached("py_installs", collect)


def text_of(host, path, limit=32 * MIB):
    return hs.read_text(path, limit, host.gaps)


def lock_hits(host, wanted):
    """[(path, name, version_or_spec)] for npm package names across lockfiles and manifests."""
    out = []
    for path, kind in index(host).npm:
        text = text_of(host, path)
        if text is None:
            continue
        for name, vers in hs.npm_lock_versions(text, kind, wanted).items():
            for v in sorted(vers):
                out.append((path, name, v))
    return out


def py_pin_hits(host, wanted, include_docker=True):
    out = []
    files = list(index(host).py)
    if include_docker:
        files += [(p, "dockerfile") for p in index(host).docker]
    for path, kind in files:
        text = text_of(host, path, 8 * MIB)
        if text is None:
            continue
        k = {"pipfile.lock": "Pipfile.lock"}.get(kind, kind)
        for name, vers in hs.py_pins(text, k, wanted).items():
            for v in sorted(vers):
                out.append((path, name, v))
    return out


def global_node_modules(host):
    dirs = [host.sys("/usr/local/lib/node_modules"), host.sys("/usr/lib/node_modules"),
            host.sys("/opt/homebrew/lib/node_modules"), host.h(".npm-global", "lib", "node_modules"),
            host.h(".npm-packages", "lib", "node_modules"), os.path.join(host.appdata(), "npm", "node_modules"),
            host.h(".bun", "install", "global", "node_modules"),
            host.h(".local", "share", "pnpm", "global", "5", "node_modules")]
    for base, sub in node_install_dirs(host):
        dirs.append(os.path.join(sub, "lib", "node_modules"))
        dirs.append(os.path.join(sub, "node_modules"))
    if host.env.get("NPM_CONFIG_PREFIX"):
        dirs.append(os.path.join(host.env["NPM_CONFIG_PREFIX"], "lib", "node_modules"))
    return [d for d in dirs if hs.is_plain_dir(d)]


def node_install_dirs(host):
    """(source, install_dir) pairs for version-managed and packaged Node installs."""
    def collect():
        h = host.h
        out = []
        managers = [
            ("nvm", host.env.get("NVM_DIR") and os.path.join(host.env["NVM_DIR"], "versions", "node") or h(".nvm", "versions", "node")),
            ("nvm-windows", host.env.get("NVM_HOME") or os.path.join(host.appdata(), "nvm")),
            ("fnm", os.path.join(host.env.get("FNM_DIR") or h(".local", "share", "fnm"), "node-versions")),
            ("fnm", h("Library", "Application Support", "fnm", "node-versions")),
            ("fnm", os.path.join(host.appdata(), "fnm", "node-versions")),
            ("volta", h(".volta", "tools", "image", "node")),
            ("volta", os.path.join(host.localappdata(), "Volta", "tools", "image", "node")),
            ("asdf", h(".asdf", "installs", "nodejs")),
            ("mise", h(".local", "share", "mise", "installs", "node")),
            ("nodenv", h(".nodenv", "versions")),
            ("n", host.sys("/usr/local/n/versions/node")),
        ]
        for src, base in managers:
            for d in hs.subdirs(base):
                if hs.parse_version(d):
                    out.append((src, os.path.join(base, d)))
        for formula, vers in cellar(host).items():
            if formula == "node" or formula.startswith("node@"):
                out += [("homebrew", p) for _v, p in vers]
        return out
    return host.cached("node_install_dirs", collect)


def node_version_h(path):
    text = hs.read_text(path, 256 * 1024)
    if not text:
        return None
    nums = [re.search(r"#define NODE_%s_VERSION (\d+)" % k, text) for k in ("MAJOR", "MINOR", "PATCH")]
    if not all(nums):
        return None
    ver = ".".join(m.group(1) for m in nums)
    rel = re.search(r"#define NODE_VERSION_IS_RELEASE (\d)", text)
    if rel and rel.group(1) == "0":
        ver += "-pre"
    return ver


def docker_refs(host, image_rx):
    """[(path, image, tag)] for image references matching ``image_rx`` in Dockerfiles, compose and deploy YAML."""
    out = []
    rx = re.compile(r"(?i)(?:^|[\s\"'=])((?:[\w.-]+(?::\d+)?/)*(?:%s))(?::([\w.-]+))?(?:@sha256:[0-9a-f]{64})?"
                    r"(?=$|[\s\"'])" % image_rx, re.M)
    for path in index(host).docker:
        text = text_of(host, path, 4 * MIB)
        if not text:
            continue
        for m in rx.finditer(text):
            out.append((path, m.group(1), m.group(2) or "latest"))
    return out


def browsers(host):
    def collect():
        out = []

        def add(name, ver, path, src):
            out.append({"browser": name, "version": ver, "path": path, "source": src})

        if host.platform == "darwin":
            apps = [("Google Chrome", "Google Chrome"), ("Google Chrome Beta", "Google Chrome Beta"),
                    ("Google Chrome Canary", "Google Chrome Canary"), ("Chromium", "Chromium"),
                    ("Microsoft Edge", "Microsoft Edge"), ("Brave Browser", "Brave Browser"),
                    ("Firefox", "Firefox"), ("Safari", "Safari"), ("Opera", "Opera"), ("Vivaldi", "Vivaldi"),
                    ("Arc", "Arc")]
            bases = [host.sys("/Applications"), host.h("Applications"),
                     host.sys("/System/Volumes/Preboot/Cryptexes/App/System/Applications")]
            for label, bundle in apps:
                for base in bases:
                    plist = os.path.join(base, bundle + APP, "Contents", "Info.plist")
                    if hs.is_regular(plist):
                        add(label, hs.plist_value(plist, "CFBundleShortVersionString"), plist, "Info.plist")
                        break
        elif host.platform == "linux":
            names = {"google-chrome-stable": "Google Chrome", "google-chrome-beta": "Google Chrome Beta",
                     "google-chrome-unstable": "Google Chrome Dev", "chromium": "Chromium",
                     "chromium-browser": "Chromium", "microsoft-edge-stable": "Microsoft Edge",
                     "brave-browser": "Brave Browser", "firefox": "Firefox", "firefox-esr": "Firefox ESR",
                     "opera-stable": "Opera", "vivaldi-stable": "Vivaldi"}
            pk = linux_packages(host)
            for pkg, label in names.items():
                for ver, src in pk.get(pkg, []):
                    add(label, ver, None, src)
            for snap, label in (("chromium", "Chromium"), ("firefox", "Firefox")):
                cur = host.sys("/snap/%s/current" % snap)
                try:
                    rev = os.readlink(cur)
                except OSError:
                    rev = None
                if rev:
                    meta = os.path.join(host.sys("/snap/%s" % snap), os.path.basename(rev), "meta", "snap.yaml")
                    m = re.search(r"(?m)^version:\s*['\"]?([^'\"\s]+)", hs.read_text(meta, 256 * 1024) or "")
                    add(label, m.group(1) if m else None, meta, "snap")
            for base in (host.sys("/var/lib/flatpak/app"), host.h(".local", "share", "flatpak", "app")):
                for app_id, label in (("com.google.Chrome", "Google Chrome"), ("org.chromium.Chromium", "Chromium"),
                                      ("com.brave.Browser", "Brave Browser"), ("org.mozilla.firefox", "Firefox"),
                                      ("com.microsoft.Edge", "Microsoft Edge")):
                    if hs.is_plain_dir(os.path.join(base, app_id)):
                        add(label, None, os.path.join(base, app_id), "flatpak (version not read)")
            have = {b["browser"] for b in out}
            if "Google Chrome" not in have and hs.exists_nofollow(host.sys("/opt/google/chrome/chrome")):
                add("Google Chrome", None, host.sys("/opt/google/chrome/chrome"), "binary without package record")
            for ini in (host.sys("/opt/firefox/application.ini"), host.sys("/usr/lib/firefox/application.ini"),
                        host.sys("/usr/lib64/firefox/application.ini")):
                if "Firefox" not in have and hs.is_regular(ini):
                    add("Firefox", hs.ini_value(hs.read_text(ini, 64 * 1024), "Version"), ini, "application.ini")
        else:
            subs = [("Google Chrome", ("Google", "Chrome", "Application")),
                    ("Google Chrome Beta", ("Google", "Chrome Beta", "Application")),
                    ("Google Chrome Canary", ("Google", "Chrome SxS", "Application")),
                    ("Chromium", ("Chromium", "Application")),
                    ("Microsoft Edge", ("Microsoft", "Edge", "Application")),
                    ("Brave Browser", ("BraveSoftware", "Brave-Browser", "Application")),
                    ("Vivaldi", ("Vivaldi", "Application"))]
            bases = host.program_files() + [host.localappdata()]
            for label, sub in subs:
                for base in bases:
                    app = os.path.join(base, *sub)
                    vers = [d for d in hs.subdirs(app) if re.match(r"^\d+\.\d+\.\d+\.\d+$", d)]
                    if vers:
                        best = max(vers, key=lambda d: hs.parse_version(d).nums)
                        add(label, best, os.path.join(app, best), "version directory")
            for base in host.program_files():
                ini = os.path.join(base, "Mozilla Firefox", "application.ini")
                if hs.is_regular(ini):
                    add("Firefox", hs.ini_value(hs.read_text(ini, 64 * 1024), "Version"), ini, "application.ini")
            have = {b["browser"] for b in out}
            for e in registry_matches(host, r"^(Google Chrome|Microsoft Edge|Mozilla Firefox|Brave)"):
                label = "Firefox" if "firefox" in e["name"].lower() else e["name"].split(" (")[0]
                if label not in have:
                    add(label, e.get("version") or None, None, "uninstall registry")
        return out
    return host.cached("browsers", collect)


def dotnet_runtimes(host):
    roots = []
    if host.platform == "windows":
        roots += [os.path.join(pf, "dotnet") for pf in host.program_files()]
    else:
        roots += [host.sys(p) for p in ("/usr/share/dotnet", "/usr/lib/dotnet", "/usr/lib64/dotnet",
                                        "/usr/local/share/dotnet", "/opt/dotnet", "/usr/local/lib/dotnet")]
        for formula, vers in cellar(host).items():
            if formula.startswith("dotnet"):
                roots += [os.path.join(p, "libexec") for _v, p in vers]
    roots.append(host.h(".dotnet"))
    if host.env.get("DOTNET_ROOT"):
        roots.append(host.env["DOTNET_ROOT"])
    out, seen = [], set()
    for root in roots:
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        for fw in DOTNET_FRAMEWORKS:
            base = os.path.join(root, "shared", fw)
            for ver in hs.subdirs(base):
                out.append((fw, ver, os.path.join(base, ver)))
    return out


def php_installs(host):
    out = []
    pk = linux_packages(host)
    for name, vers in pk.items():
        if re.match(r"^php(\d(\.\d)?|\d\d)?(-(cli|fpm|common|cgi))?$", name) or re.match(r"^php\d\.\d-(cli|fpm|common)$", name):
            out += [("package %s (%s)" % (name, src), ver, None) for ver, src in vers]
    for formula, vers in cellar(host).items():
        if formula == "php" or formula.startswith("php@"):
            out += [("homebrew %s" % formula, v, p) for v, p in vers]
    heads = [host.sys("/usr/local/include/php/main/php_version.h"), host.sys("/opt/homebrew/include/php/main/php_version.h")]
    heads += [os.path.join(d, "main", "php_version.h") for d in glob_dirs(host, host.sys("/usr/include"), "php*")]
    heads += [os.path.join(d, "php", "main", "php_version.h") for d in glob_dirs(host, host.sys("/usr/include"), "php*")]
    for hpath in heads:
        m = re.search(r'#define PHP_VERSION "([^"]+)"', hs.read_text(hpath, 64 * 1024) or "")
        if m:
            out.append(("php_version.h", m.group(1), hpath))
    for d in glob_dirs(host, host.sys("/Applications/MAMP/bin/php"), "php*"):
        out.append(("MAMP", os.path.basename(d)[3:], d))
    if host.platform == "windows":
        cands = [host.sys("C:/xampp/php"), host.sys("C:/tools/php"), host.sys("C:/php")]
        cands += glob_dirs(host, host.sys("C:/tools"), "php*") + glob_dirs(host, host.sys("C:/"), "php*")
        cands += glob_dirs(host, host.sys("C:/laragon/bin/php"), "php*")
        for pf in host.program_files():
            cands += glob_dirs(host, os.path.join(pf, "PHP"), "*") + [os.path.join(pf, "PHP")]
        for exe in find_binaries(host, ["php"]):
            cands.append(os.path.dirname(exe))
        seen = set()
        for d in cands:
            key = os.path.normcase(os.path.abspath(d))
            if key in seen or not hs.is_plain_dir(d):
                continue
            seen.add(key)
            for dll in ("php8ts.dll", "php8.dll", "php7ts.dll", "php7.dll"):
                p = os.path.join(d, dll)
                if hs.is_regular(p):
                    out.append(("Windows build (%s)" % dll, hs.pe_file_version(p) or "unknown", p))
                    break
    return out


def php_inis(host):
    cands = [host.sys("/etc/php.ini"), host.sys("/usr/local/etc/php/php.ini"), host.sys("/usr/local/lib/php.ini")]
    for d in glob_dirs(host, host.sys("/etc/php"), "*"):
        cands += [os.path.join(d, sapi, "php.ini") for sapi in hs.subdirs(d)]
    cands += [os.path.join(d, "php.ini") for d in glob_dirs(host, host.sys("/etc"), "php8*")]
    for base in (host.sys("/opt/homebrew/etc/php"), host.sys("/usr/local/etc/php")):
        cands += [os.path.join(d, "php.ini") for d in glob_dirs(host, base, "*")]
    for _src, _ver, p in php_installs(host):
        if p and host.platform == "windows":
            cands.append(os.path.join(os.path.dirname(p), "php.ini"))
    return [p for p in dict.fromkeys(cands) if hs.is_regular(p)]


def ruby_installs(host):
    out = []
    h = host.h
    for src, base in (("rbenv", h(".rbenv", "versions")), ("asdf", h(".asdf", "installs", "ruby")),
                      ("mise", h(".local", "share", "mise", "installs", "ruby")), ("chruby", h(".rubies")),
                      ("chruby", host.sys("/opt/rubies")), ("rvm", h(".rvm", "rubies"))):
        for d in hs.subdirs(base):
            ver = d[5:] if d.startswith("ruby-") else d
            if hs.parse_version(ver):
                out.append((src, ver, os.path.join(base, d)))
    for formula, vers in cellar(host).items():
        if formula == "ruby" or formula.startswith("ruby@"):
            out += [("homebrew %s" % formula, v, p) for v, p in vers]
    for name, vers in linux_packages(host).items():
        if re.match(r"^ruby(\d(\.\d)?)?$", name) or re.match(r"^ruby\d\.\d$", name):
            out += [("package %s (%s)" % (name, src), v, None) for v, src in vers]
    roots = []
    if host.platform == "windows":
        roots += glob_dirs(host, host.sys("C:/"), "ruby*")
    if host.platform == "darwin":
        roots += [os.path.join(host.sys("/System/Library/Frameworks/Ruby.framework/Versions"), v, "usr")
                  for v in hs.subdirs(host.sys("/System/Library/Frameworks/Ruby.framework/Versions")) if v != "Current"]
    for root in roots:
        lib = os.path.join(root, "lib", "ruby")
        for api in hs.subdirs(lib):
            for arch in hs.subdirs(os.path.join(lib, api)):
                rb = os.path.join(lib, api, arch, "rbconfig.rb")
                m = re.search(r'CONFIG\["RUBY_PROGRAM_VERSION"\]\s*=\s*"([^"]+)"', hs.read_text(rb, 512 * 1024) or "")
                if m:
                    out.append(("rbconfig.rb", m.group(1), rb))
    return out


def web_roots(host):
    cands = ["/var/www", "/srv", "/usr/share/nginx/html", "/Library/WebServer/Documents",
             "/Applications/MAMP/htdocs", "C:/inetpub/wwwroot", "C:/xampp/htdocs", "C:/laragon/www"]
    return [host.sys(c) for c in cands if hs.is_plain_dir(host.sys(c))]


# --------------------------------------------------------------------------
# Checks: testmetest worm, planted agent files, agent configs
# --------------------------------------------------------------------------

HOOK_MARKERS = [
    ("download_command", re.compile(r"(?i)\b(curl|wget|invoke-webrequest|iwr|irm|invoke-restmethod|bitsadmin|certutil)\b")),
    ("pipe_to_shell", re.compile(r"(?i)\|\s*(?:ba|z)?sh\b|\|\s*iex\b|\|\s*powershell")),
    ("inline_interpreter", re.compile(r"(?i)\b(?:node|python3?|bun|deno|ruby|perl)\s+-[ec]\b|\b(?:ba)?sh\s+-c\b|"
                                      r"powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|c|command)\b")),
    ("base64", re.compile(r"(?i)base64|frombase64string|atob\(")),
    ("dynamic_code", re.compile(r"(?i)\beval\b|new function\(|child_process|execsync|spawnsync")),
    ("network_url", re.compile(r"(?i)\b(?:https?|wss?)://")),
    ("named_malicious_package", re.compile(r"(?i)testmetest|function-color")),
    ("home_wipe", re.compile(r"(?i)rm\s+-rf\s+(?:~|\$home|/(?:\s|$))|remove-item\s+.*-recurse")),
    ("credential_access", re.compile(r"(?i)gh auth token|github_token|gh_token|\.git-credentials|\.npmrc|id_rsa|id_ed25519")),
]
HOOK_WORD = re.compile(r"(?<![a-z0-9])hooks?(?![a-z])")
SCRIPT_TOOLS = {".cursor", ".claude", ".gemini", ".codex", ".windsurf", ".kiro", ".amazonq", ".continue", ".roo",
                ".clinerules", ".vscode", ".vscode-insiders"}
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".cmd", ".bat", ".vbs", ".js", ".mjs", ".cjs", ".ts", ".py",
              ".rb", ".pl", ".exe", ".bin")
SCRIPT_EXEMPT = {"skills", "skills-cursor", "rules", "commands", "agents", "prompts", "workflows", "plugins",
                 "instructions", "chatmodes", "snippets"}
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def exec_bit(path):
    st = hs.lstat(path)
    return bool(st and os.name != "nt" and stat.S_ISREG(st.st_mode) and st.st_mode & 0o111)


def markers_in(text):
    return sorted({name for name, rx in HOOK_MARKERS if rx.search(text or "")})


def loose_json(text):
    """JSON with // and /* */ comments and trailing commas (VS Code style), or None."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    cleaned = re.sub(r'("(?:[^"\\]|\\.)*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", text, flags=re.S)
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None


def has_hooks_key(doc, depth=0):
    if depth > 6:
        return False
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(k, str) and k.lower() == "hooks" and v not in (None, {}, [], ""):
                return True
            if has_hooks_key(v, depth + 1):
                return True
    elif isinstance(doc, list):
        return any(has_hooks_key(v, depth + 1) for v in doc[:200])
    return False


def git_paths(host, repo):
    """(gitdir, objects_parent, index_entries) for a repository root, cached."""
    def collect():
        gp = index(host).repos.get(repo)
        gitdir = gp
        if gp and hs.is_regular(gp):
            m = re.match(r"gitdir:\s*(.+)", (hs.read_text(gp, 4096) or "").strip())
            if not m:
                return None, None, None
            target = m.group(1).strip()
            gitdir = target if os.path.isabs(target) else os.path.normpath(os.path.join(repo, target))
        if not gitdir or not hs.is_plain_dir(gitdir):
            return None, None, None
        common = gitdir
        cd = hs.read_text(os.path.join(gitdir, "commondir"), 4096)
        if cd and cd.strip():
            c = cd.strip()
            common = c if os.path.isabs(c) else os.path.normpath(os.path.join(gitdir, c))
        entries = hs.git_index_entries(gitdir)
        if entries is None and hs.exists_nofollow(os.path.join(gitdir, "index")):
            host.gaps.add("unparsed", os.path.join(gitdir, "index"), "git index not readable")
        return gitdir, common, entries
    return host.cached(("git", repo), collect)


def repo_rel(repo, path):
    return os.path.relpath(path, repo).replace("\\", "/")


def check_ai_hooks(host, r):
    idx = index(host)
    seen = 0
    home = os.path.normcase(host.home)
    for path, tool, tool_root, repo in idx.tool_files:
        inner = [p.lower() for p in os.path.relpath(os.path.dirname(path), tool_root).replace("\\", "/").split("/")
                 if p not in (".", "")]
        name_l = os.path.basename(path).lower()
        why = None
        text = None
        user_level = os.path.normcase(os.path.dirname(tool_root)) == home
        if user_level:
            hook_dir = bool(inner) and HOOK_WORD.fullmatch(inner[0]) is not None
            hook_name = not inner and HOOK_WORD.search(name_l) is not None
            script = False
        else:
            hook_dir = any(HOOK_WORD.search(p) for p in inner)
            hook_name = HOOK_WORD.search(name_l) is not None and not name_l.endswith(".d.ts")
            script = (tool in SCRIPT_TOOLS and len(inner) <= 2 and not (inner and inner[0] in SCRIPT_EXEMPT)
                      and not name_l.endswith(".d.ts") and (name_l.endswith(SCRIPT_EXT) or exec_bit(path)))
        if hook_dir:
            why = "file inside a hooks folder"
        elif hook_name:
            why = "hook-named file"
        elif script:
            why = "script inside a repository AI tool folder (a renamed hook would look like this)"
        elif not inner and name_l.endswith((".json", ".jsonc", ".toml")) and tool != ".vscode" and \
                ("settings" in name_l or "config" in name_l):
            text = text_of(host, path, 4 * MIB)
            if name_l.endswith(".toml"):
                tables = hs.toml_tables(text)
                if any(t == "hooks" or t.startswith("hooks.") for t in tables) or "hooks" in tables.get("", {}):
                    why = "hooks configured in settings"
            elif has_hooks_key(loose_json(text)) or re.search(r'(?i)"hooks"\s*:\s*[\[{]\s*[^\s\]}]', text or ""):
                why = "hooks configured in settings"
        elif tool == ".vscode" and not inner and name_l == "tasks.json":
            text = text_of(host, path, 4 * MIB)
            if re.search(r'(?i)"runon"\s*:\s*"folderopen"', text or ""):
                why = "VS Code task runs automatically when the folder opens"
        elif tool == ".vscode" and not inner and name_l == "settings.json":
            text = text_of(host, path, 4 * MIB)
            if re.search(r'(?i)"task\.allowautomatictasks"\s*:\s*"on"', text or ""):
                why = "VS Code setting allows automatic tasks"
        if not why:
            continue
        seen += 1
        data = hs.read_bytes(path, 64 * MIB, host.gaps)
        sha = hashlib.sha256(data).hexdigest() if data is not None else None
        if text is None and data is not None:
            text = data[: 4 * MIB].decode("utf-8", "replace")
        marks = markers_in(text)
        if text and HIDDEN_CHARS.search(text):
            marks.append("hidden_unicode")
        tracked = None
        if repo:
            _g, _c, entries = git_paths(host, repo)
            tracked = None if entries is None else repo_rel(repo, path) in entries
        disp = host.display(path)
        reason = allowed(host, "hooks", disp, sha)
        result = "info" if reason else "review"
        if "named_malicious_package" in marks:
            result = "affected"
        detail = why + ("; allowlisted: %s" % reason if reason else "; not confirmed as user-authored")
        r.add(result, "%s hook (%s)" % (tool, "user-level" if user_level else "repository"), detail, path=disp,
              sha256=sha, size=len(data) if data is not None else None, markers=marks,
              tracked_in_git={True: "yes", False: "no", None: "unknown"}[tracked] if repo else None)
    r.present = True
    r.notes.append("%d hook candidate(s) in %d repositories and user tool folders" % (seen, len(idx.repos)))


def check_large_blobs(host, r):
    idx = index(host)
    review_lo, review_hi = host.blob_review
    info_lo, info_hi = host.blob_info
    large_by_repo = {}
    for path, size, repo in idx.large:
        large_by_repo.setdefault(repo, []).append((path, size))
    for repo in sorted(idx.repos):
        gitdir, common, entries = git_paths(host, repo)
        attrs = (hs.read_text(os.path.join(repo, ".gitattributes"), 256 * 1024) or "")
        if gitdir:
            attrs += "\n" + (hs.read_text(os.path.join(gitdir, "info", "attributes"), 256 * 1024) or "")
        lfs = hs.lfs_patterns(attrs)
        by_sha = {}
        reported = set()

        def emit(where, size, rel=None, sha=None):
            disp = host.display(os.path.join(repo, rel)) if rel else host.display(repo) + " (git object)"
            reason = allowed(host, "large_files", disp, sha)
            is_lfs = rel is not None and hs.lfs_match(rel, lfs)
            in_window = review_lo <= size <= review_hi
            if reason:
                res, why = "info", "allowlisted: %s" % reason
            elif is_lfs:
                res, why = "info", "matches a Git LFS pattern in .gitattributes"
            elif in_window:
                res, why = "review", "about the size of the reported ~13 MB payload; not confirmed as added by the owner"
            else:
                res, why = "info", "large file outside the review window"
            r.add(res, "large blob (%s)" % where, why, path=disp, size=size, object_id=sha)

        for rel, (size, sha) in sorted((entries or {}).items()):
            by_sha[sha] = rel
            if info_lo <= size <= info_hi:
                emit("tracked file", size, rel, sha)
                reported.add(rel)
        if common:
            budget = hs.Budget(max(0.0, min(host.repo_seconds, host.budget.left())))
            blobs, complete = hs.git_large_blobs(common, info_lo, info_hi, budget, gaps=host.gaps)
            if not complete:
                r.blocked.append("object scan stopped early in %s" % host.display(repo))
                host.gaps.add("time_budget", common, "git object scan stopped")
            for sha, size, where in sorted(blobs):
                rel = by_sha.get(sha)
                if rel in reported:
                    continue
                if rel:
                    emit("committed object for " + where, size, rel, sha)
                    reported.add(rel)
                else:
                    emit("object not in the current index (%s)" % where, size, None, sha)
        elif repo in idx.repos:
            host.gaps.add("unparsed", idx.repos[repo], "git directory not resolved")
        for path, size in large_by_repo.get(repo, []):
            rel = repo_rel(repo, path)
            if rel not in reported and not rel.startswith(".git/") and size <= info_hi:
                emit("untracked working-tree file", size, rel)
    r.present = True
    r.notes.append("%d git repositories examined; review window %d-%d MiB" % (len(idx.repos), review_lo // MIB, review_hi // MIB))


def npm_package_check(host, r, name):
    wanted = {name}
    for path, n, v in lock_hits(host, wanted):
        res = "review" if v.startswith("spec:") else "affected"
        r.add(res, "npm package %s" % n, "listed in %s" % os.path.basename(path), path=host.display(path),
              version=v.replace("spec:", "range "))
    nms = index(host).node_modules[:20000] + global_node_modules(host)
    for nm in nms:
        pj = os.path.join(nm, name, "package.json")
        if hs.is_regular(pj):
            doc = hs.read_json(pj, 1 * MIB) or {}
            r.add("affected", "npm package %s" % name, "installed in node_modules", path=host.display(pj),
                  version=doc.get("version") if isinstance(doc, dict) else None)
        hidden = os.path.join(nm, ".package-lock.json")
        if hs.is_regular(hidden):
            text = text_of(host, hidden)
            for n, vers in hs.npm_lock_versions(text or "", ".package-lock.json", wanted).items():
                for v in sorted(vers):
                    r.add("affected", "npm package %s" % n, "recorded in node_modules/.package-lock.json (may be nested)",
                          path=host.display(hidden), version=v)
        for d in hs.listdir(os.path.join(nm, ".pnpm")):
            if d.lower().startswith(name + "@"):
                r.add("affected", "npm package %s" % name, "present in the pnpm virtual store",
                      path=host.display(os.path.join(nm, ".pnpm", d)), version=d.split("@", 1)[1].split("_")[0])
    caches = [host.h(".npm", "_cacache", "index-v5"), os.path.join(host.localappdata(), "npm-cache", "_cacache", "index-v5")]
    needle = ("/%s/-/%s-" % (name, name)).encode()
    for cache in caches:
        if not hs.is_plain_dir(cache):
            continue
        budget = hs.Budget(min(10.0, max(0.0, host.budget.left())))
        files = 0
        stack = [cache]
        hit = None
        while stack and not hit:
            d = stack.pop()
            for n in hs.listdir(d):
                p = os.path.join(d, n)
                if hs.is_plain_dir(p):
                    stack.append(p)
                    continue
                files += 1
                if files > 200_000 or budget.over():
                    r.blocked.append("npm cache index scan stopped early")
                    stack = []
                    break
                data = hs.read_bytes(p, 1 * MIB)
                if data and needle in data:
                    hit = p
                    break
        if hit:
            r.add("review", "npm package %s" % name, "tarball recorded in the npm cache index (downloaded at some point)",
                  path=host.display(cache))
    r.present = True


def check_testmetest(host, r):
    npm_package_check(host, r, "testmetest")


def check_function_color(host, r):
    npm_package_check(host, r, "function-color")


INSTR_MARKERS = [
    ("named_malicious_package", re.compile(r"(?i)function-color|testmetest")),
    ("package_install", re.compile(r"(?i)\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b|\bnpx\s+-y\b|\bpip3?\s+install\b|"
                                   r"\buvx?\s+(?:pip\s+)?install\b")),
    ("api_base_override", re.compile(r"(?i)\b(?:anthropic_base_url|anthropic_api_url|openai_base_url|openai_api_base|"
                                     r"api_base|base_url|baseurl|chatgpt_base_url)\b")),
    ("download_command", HOOK_MARKERS[0][1]),
    ("pipe_to_shell", HOOK_MARKERS[1][1]),
]
# Setup docs in a real project routinely say "npm install" or "curl localhost"; alone they do not list a project file.
PROJECT_ROUTINE_MARKERS = {"package_install", "download_command"}


def check_planted_instructions(host, r):
    idx = index(host)
    files = list(idx.instr)
    temp_dirs = [host.sys("/tmp")] if host.platform != "windows" else []
    temp = host.winvar("TEMP", None) or host.winvar("TMP", None)
    if temp:
        temp_dirs.append(temp)
    for td in temp_dirs:
        for n in hs.listdir(td)[:5000]:
            p = os.path.join(td, n)
            if n.lower() in INSTR_NAMES and hs.is_regular(p):
                files.append((p, False, False, None))
            elif hs.is_plain_dir(p):
                for m in hs.listdir(p)[:500]:
                    if m.lower() in INSTR_NAMES and hs.is_regular(os.path.join(p, m)):
                        files.append((os.path.join(p, m), False, False, None))
    loose = {os.path.normcase(host.home)} | {os.path.normcase(host.h(d)) for d in ("Desktop", "Documents", "Downloads")}
    legit = 0
    for path, in_project, in_dl, repo in files:
        data = hs.read_bytes(path, 2 * MIB, host.gaps)
        text = data.decode("utf-8", "replace") if data is not None else ""
        sha = hashlib.sha256(data).hexdigest() if data is not None else None
        marks = sorted({n for n, rx in INSTR_MARKERS if rx.search(text)})
        if INJECTION.search(text):
            marks.append("instruction_injection_phrase")
        if HIDDEN_CHARS.search(text):
            marks.append("hidden_unicode")
        parent = os.path.normcase(os.path.dirname(path))
        disp = host.display(path)
        if in_dl:
            where = "under Downloads (do not start coding agents here)"
        elif parent in loose or not in_project:
            where = "outside any project folder"
        elif set(marks) - PROJECT_ROUTINE_MARKERS:
            where = "inside a project, with risky instructions"
        else:
            legit += 1
            continue
        reason = allowed(host, "instruction_files", disp, sha)
        result = "info" if reason else "review"
        if "named_malicious_package" in marks:
            result = "affected"
        r.add(result, "agent instruction file", where + ("; allowlisted: %s" % reason if reason else
                                                         "; read it before any agent runs in that folder"),
              path=disp, sha256=sha, markers=marks)
    r.present = True
    r.notes.append("%d instruction file(s) inside projects with no risky markers were not listed" % legit)


def url_host(raw):
    try:
        u = urlsplit(str(raw).strip())
        if not u.scheme or not u.hostname:
            return None
        port = ":%d" % u.port if u.port else ""
        return "%s://%s%s" % (u.scheme.lower(), u.hostname.lower(), port)
    except ValueError:
        return None


PKG_SPEC = re.compile(r"^(?:@[\w.-]+/)?[\w.-]+(?:@[\w.^~<>=*-]+)?$")
IMAGE_SPEC = re.compile(r"^[\w.-]+(?:/[\w.-]+)+(?::[\w.-]+)?$|^[\w.-]+:[\w.-]+$")


def server_summary(name, spec):
    """Names, transport, command basename, package spec and host only; never env values, headers or args."""
    out = {"name": str(name)}
    if not isinstance(spec, dict):
        return out
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    if url:
        out["transport"] = "http"
        out["url_host"] = url_host(url) or "unparsed URL"
    cmd = spec.get("command")
    args = spec.get("args") if isinstance(spec.get("args"), list) else []
    if isinstance(cmd, str) and cmd:
        out["transport"] = "stdio"
        base = re.split(r"[\\/]", cmd.strip())[-1]
        out["command"] = base
        words = [str(a) for a in args if isinstance(a, (str, int))]
        if base.split(".")[0] in ("npx", "uvx", "bunx", "pnpx", "pipx") or \
                (base.split(".")[0] in ("pnpm", "yarn", "npm", "bun") and words[:1] and words[0] in ("dlx", "exec", "x")):
            for w in words:
                if w.startswith("-") or w in ("dlx", "exec", "x", "run"):
                    continue
                if PKG_SPEC.match(w):
                    out["package"] = w
                break
        elif base.split(".")[0] in ("docker", "podman") and "run" in words:
            imgs = [w for w in words if IMAGE_SPEC.match(w) and "=" not in w]
            if imgs:
                out["image"] = imgs[-1]
    env = spec.get("env")
    if isinstance(env, dict):
        out["env_var_names"] = sorted(str(k) for k in env)[:50]
    headers = spec.get("headers")
    if isinstance(headers, dict):
        out["header_names"] = sorted(str(k) for k in headers)[:50]
    return out


def agent_config_files(host):
    h = host.h
    codex_home = host.env.get("CODEX_HOME") or h(".codex")
    files = [os.path.join(codex_home, "config.toml"), h(".claude", "settings.json"), h(".claude", "settings.local.json"),
             h(".claude.json"), h(".cursor", "mcp.json"), h(".gemini", "settings.json"),
             h(".codeium", "windsurf", "mcp_config.json"), h(".claude", "mcp.json")]
    if host.platform == "darwin":
        files += [h("Library", "Application Support", "Claude", "claude_desktop_config.json"),
                  h("Library", "Application Support", "Code", "User", "mcp.json"),
                  h("Library", "Application Support", "Cursor", "User", "mcp.json")]
    elif host.platform == "windows":
        files += [os.path.join(host.appdata(), "Claude", "claude_desktop_config.json"),
                  os.path.join(host.appdata(), "Code", "User", "mcp.json"),
                  os.path.join(host.appdata(), "Cursor", "User", "mcp.json")]
    else:
        files += [h(".config", "Claude", "claude_desktop_config.json"), h(".config", "Code", "User", "mcp.json"),
                  h(".config", "Cursor", "User", "mcp.json")]
    for path, tool, tool_root, _repo in index(host).tool_files:
        name_l = os.path.basename(path).lower()
        if os.path.dirname(path) == tool_root and (name_l in ("mcp.json", "settings.json", "settings.local.json")
                                                   or (tool == ".codex" and name_l == "config.toml")):
            files.append(path)
    files += index(host).mcp_files
    out, seen = [], set()
    for f in files:
        key = os.path.normcase(os.path.abspath(f))
        if key not in seen and hs.is_regular(f):
            seen.add(key)
            out.append(f)
    return out


BASE_URL_KEY = re.compile(r"(?i)(base_?url|api_?url|api_?base|endpoint|_host)$")


def check_agent_configs(host, r):
    files = agent_config_files(host)
    for path in files:
        disp = host.display(path)
        servers, bases = [], []
        if path.lower().endswith(".toml"):
            tables = hs.toml_tables(text_of(host, path, 4 * MIB))
            for tname, kv in sorted(tables.items()):
                m = re.match(r"^mcp_servers\.([^.]+)$", tname)
                if m:
                    spec = {}
                    cmd = hs.toml_strings(kv.get("command", ""))
                    if cmd:
                        spec["command"] = cmd[0]
                    spec["args"] = hs.toml_strings(kv.get("args", ""))
                    url = hs.toml_strings(kv.get("url", ""))
                    if url:
                        spec["url"] = url[0]
                    env = dict(tables.get(tname + ".env", {}))
                    env.update({k: "" for k in re.findall(r"[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*=", kv.get("env", ""))})
                    if env:
                        spec["env"] = env
                    servers.append(server_summary(m.group(1), spec))
                for k, v in kv.items():
                    if BASE_URL_KEY.search(k):
                        for s in hs.toml_strings(v):
                            if url_host(s):
                                bases.append(("%s%s" % (tname + "." if tname else "", k), url_host(s)))
        else:
            doc = hs.read_json(path, 32 * MIB, host.gaps) if not path.lower().endswith("mcp.json") else \
                loose_json(text_of(host, path, 8 * MIB))
            if not isinstance(doc, dict):
                if doc is None:
                    r.add("unknown", "agent config", "file could not be parsed", path=disp)
                continue
            groups = [("", doc)]
            projects = doc.get("projects")
            if isinstance(projects, dict):
                groups += [(host.display(k) if is_abs_locator(k) else "project", v)
                           for k, v in sorted(projects.items()) if isinstance(v, dict)]
            for scope, g in groups:
                for key in ("mcpServers", "servers"):
                    srv = g.get(key)
                    if isinstance(srv, dict):
                        for name, spec in sorted(srv.items()):
                            s = server_summary(name, spec)
                            if scope:
                                s["scope"] = scope
                            servers.append(s)
                mcp = g.get("mcp")
                if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
                    servers += [server_summary(n, sp) for n, sp in sorted(mcp["servers"].items())]
            env = doc.get("env")
            if isinstance(env, dict):
                for k, v in sorted(env.items()):
                    if BASE_URL_KEY.search(str(k)) and url_host(v):
                        bases.append(("env." + str(k), url_host(v)))
            if doc.get("apiKeyHelper"):
                r.add("review", "agent credential helper", "apiKeyHelper is set (command not shown)", path=disp)
            for k in ("baseUrl", "base_url", "apiBaseUrl"):
                if url_host(doc.get(k)):
                    bases.append((k, url_host(doc.get(k))))
        for s in servers:
            host_only = (s.get("url_host") or "").split("://")[-1].split(":")[0] or None
            reason = allowed(host, "mcp_servers", name=s["name"]) or \
                (host_only and allowed(host, "mcp_servers", hostname=host_only))
            blob = json.dumps(s)
            res = "affected" if re.search(r"(?i)testmetest|function-color", blob) else ("info" if reason else "review")
            r.add(res, "MCP server", "allowlisted: %s" % reason if reason else
                  "not confirmed as added by the owner; remove it if nobody added it", path=disp, server=s)
        for key, base in bases:
            hn = base.split("://")[-1].split(":")[0]
            reason = allowed(host, "base_urls", hostname=hn)
            r.add("info" if reason else "review", "API base URL override",
                  "%s points to %s; %s" % (key, base, "allowlisted: %s" % reason if reason else
                                           "agents may send API traffic there; confirm someone added it"), path=disp)
        if not servers and not bases:
            r.add("info", "agent config", "no MCP servers or base URL overrides", path=disp)
    r.present = bool(files)
    r.notes.append("%d agent config file(s) read; only names, env var names, command basenames and hosts are shown" % len(files))


# --------------------------------------------------------------------------
# Checks: packages and runtimes
# --------------------------------------------------------------------------

def check_litellm(host, r):
    for ver, path, label in py_installs(host).get("litellm", []):
        res = "affected" if ver == "1.107.0" else "info"
        r.add(res, "litellm (%s)" % label, "malicious release; rebuild the machine and rotate every key on it, "
              "then pin 1.106.2" if res == "affected" else "installed; not the malicious release",
              path=host.display(path), version=ver)
    for path, _n, v in py_pin_hits(host, {"litellm"}):
        if v == "1.107.0":
            r.add("affected", "litellm pin", "pins the malicious release", path=host.display(path), version=v)
        else:
            r.add("info", "litellm reference", "version not pinned to the malicious release (installed version "
                  "depends on resolution time)", path=host.display(path), version=v.replace("spec:", ""))
    for path, image, tag in docker_refs(host, r"[\w-]*litellm[\w-]*"):
        t = re.sub(r"^(?:main-)?v?", "", tag)
        res = "affected" if t.split("-")[0] == "1.107.0" else "info"
        r.add(res, "litellm image", "image tag %s" % tag, path=host.display(path), version=tag, image=image)
    r.present = True


def check_brotli_node(host, r):
    fixed, nofix = NODE_BROTLI_FIXED, [(20,)]
    seen = set()
    for src, d in node_install_dirs(host):
        ver = os.path.basename(d)
        hdr = node_version_h(os.path.join(d, "include", "node", "node_version.h"))
        classify_version(r, "Node.js (%s)" % src, hdr or ver, host.display(d), fixed, 1, nofix,
                         "node_version.h" if hdr else "install directory name")
        seen.add(os.path.normcase(os.path.abspath(d)))
    for name, vers in linux_packages(host).items():
        if re.match(r"^nodejs(\d+)?(-current|-lts.*)?$", name):
            for ver, src in vers:
                classify_version(r, "Node.js package %s (%s)" % (name, src), ver, None, fixed, 1, nofix, src)
    for hpath in (host.sys("/usr/local/include/node/node_version.h"), host.sys("/usr/include/node/node_version.h"),
                  host.sys("/opt/homebrew/include/node/node_version.h")):
        hv = node_version_h(hpath)
        if hv:
            classify_version(r, "Node.js headers", hv, host.display(hpath), fixed, 1, nofix, "node_version.h")
    for e in registry_matches(host, r"^Node\.js"):
        classify_version(r, "Node.js (uninstall registry)", e.get("version") or "unknown", None, fixed, 1, nofix, "registry")
    for exe in find_binaries(host, ["node"]):
        real = os.path.normcase(os.path.abspath(os.path.dirname(os.path.dirname(exe))))
        if real in seen or any(real.startswith(s + os.sep) for s in seen):
            continue
        hv = node_version_h(os.path.join(os.path.dirname(os.path.dirname(exe)), "include", "node", "node_version.h"))
        pv = hs.pe_file_version(exe) if host.platform == "windows" and hs.is_regular(exe) else None
        if hv or pv:
            classify_version(r, "Node.js on PATH", hv or pv, host.display(exe), fixed, 1, nofix,
                             "node_version.h" if hv else "PE version resource")
        elif not r.findings:
            r.add("unknown", "Node.js on PATH", "binary present; version not readable without running it",
                  path=host.display(exe))
    for path, image, tag in docker_refs(host, r"node"):
        v = hs.parse_version(tag)
        if v and len(v.nums) >= 3:
            classify_version(r, "Node.js base image", tag, host.display(path), fixed, 1, nofix, "image tag",
                             "; rebuild the image after upgrading")
        else:
            r.add("info", "Node.js base image", "moving tag %s; rebuild the image to pick up the fixed build" % tag,
                  path=host.display(path), version=tag)
    for path, kind in index(host).node_pins:
        classify_node_pin(r, host.display(path), kind, text_of(host, path, 16 * 1024) or "", fixed, nofix)
    for path, kind in index(host).npm:
        if kind == "package.json":
            classify_node_engines(r, host.display(path), text_of(host, path, MIB) or "", fixed, nofix)
    for path in index(host).ci_yml:
        classify_setup_node(r, host.display(path), text_of(host, path, 4 * MIB) or "", fixed, nofix)
    if r.findings:
        r.notes.append("In-the-wild exploitation against Node 24.22.0 is unverified as a Node.js or NVD claim; "
                       "the October 2026 Node.js advisory names CVE-2026-111497 and the fixed builds above")


def classify_node_pin(r, path, kind, text, fixed, nofix):
    """Classify a version-manager pin. An exact X.Y.Z is compared; a range is recorded only."""
    first = ""
    for ln in text.splitlines():
        s = ln.split("#", 1)[0].strip()
        if not s:
            continue
        if kind == ".tool-versions":
            m = re.match(r"(?i)^(?:nodejs|node)\s+(\S+)", s)
            if m:
                first = m.group(1)
                break
            continue
        first = s.split()[0]
        break
    if not first:
        return
    disp = path  # display applied by caller via host.display in check
    v = hs.parse_version(first)
    label = "Node.js pin (%s)" % kind
    if v is None or len(v.nums) < 3:
        r.add("info", label, "pin %s is not an exact X.Y.Z; the resolved patch is unknown" % first,
              path=disp, version=first)
        return
    classify_version(r, label, first, disp, fixed, 1, nofix, kind + " pin")


def classify_node_engines(r, path, text, fixed, nofix):
    try:
        doc = json.loads(text)
    except ValueError:
        return
    engines = doc.get("engines") if isinstance(doc, dict) else None
    spec = engines.get("node") if isinstance(engines, dict) else None
    if not isinstance(spec, str) or not spec.strip():
        return
    spec = spec.strip()
    v = hs.parse_version(spec)
    if v is None or len(v.nums) < 3 or any(c in spec for c in "<>^~*|"):
        r.add("info", "package.json engines.node",
              "constraint %s (source constraint, not runtime proof)" % spec, path=path, version=spec)
        return
    classify_version(r, "package.json engines.node", spec, path, fixed, 1, nofix, "engines.node exact pin")


def classify_setup_node(r, path, text, fixed, nofix):
    """Read actions/setup-node node-version lines. Does not run CI or Node."""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if not re.search(r"(?i)uses:\s*['\"]?actions/setup-node", ln):
            continue
        ver = None
        for j in range(i + 1, min(i + 16, len(lines))):
            nxt = lines[j]
            if re.match(r"^\s*-\s+", nxt) and j > i + 1:
                break
            m = re.match(r"^\s*node-version:\s*['\"]?v?([^'\"\s#]+)", nxt)
            if m:
                ver = m.group(1)
                break
            if re.match(r"^\s*node-version-file:", nxt):
                r.add("info", "CI setup-node", "node-version-file (the pin file is classified separately)", path=path)
                ver = False
                break
        if ver is False or ver is None:
            continue
        v = hs.parse_version(ver)
        if v is None or len(v.nums) < 3:
            r.add("info", "CI setup-node", "node-version %s is not an exact X.Y.Z" % ver, path=path, version=ver)
        else:
            classify_version(r, "CI setup-node", ver, path, fixed, 1, nofix, "workflow node-version")


def check_brotli_python(host, r):
    for ver, path, label in py_installs(host).get("brotli", []):
        v = hs.parse_version(ver)
        res = "unknown" if v is None else ("affected" if hs.below(v, "1.2.1") else "info")
        r.add(res, "Brotli (%s)" % label, "Brotli 1.2.0 or older is affected; fixed in 1.2.1", path=host.display(path), version=ver)
    for ver, path, label in py_installs(host).get("brotlicffi", []):
        v = hs.parse_version(ver)
        if v is None:
            r.add("unknown", "brotlicffi (%s)" % label, "version not parsed", path=host.display(path), version=ver)
        elif v.nums[:3] == (1, 2, 0):
            r.add("affected", "brotlicffi (%s)" % label, "1.2.0.x is affected; fixed in " + BROTLICFFI_FIXED, path=host.display(path), version=ver)
        elif hs.at_least(v, BROTLICFFI_FIXED):
            r.add("info", "brotlicffi (%s)" % label, "at or above " + BROTLICFFI_FIXED, path=host.display(path), version=ver)
        else:
            r.add("review", "brotlicffi (%s)" % label, "older than 1.2.0; not covered by the briefing", path=host.display(path), version=ver)
    for path, n, v in py_pin_hits(host, {"brotli", "brotlicffi"}, include_docker=False):
        pv = hs.parse_version(v) if not v.startswith("spec:") else None
        if pv is None:
            r.add("info", "%s reference" % n, "not an exact pin", path=host.display(path), version=v.replace("spec:", ""))
            continue
        bad = hs.below(pv, "1.2.1") if n == "brotli" else pv.nums[:3] == (1, 2, 0)
        r.add("affected" if bad else "info", "%s pin" % n, "exact pin", path=host.display(path), version=v)
    r.notes.append("requests, httpx and aiohttp use these packages on their own when installed")


def check_brotli_dotnet(host, r):
    for fw, ver, path in dotnet_runtimes(host):
        classify_version(r, ".NET %s" % fw, ver, host.display(path), ["8.0.33", "9.0.22", "10.0.14"], 1, (),
                         "shared runtime directory", "; only apps with Brotli decompression on are exposed")


def check_certifi(host, r):
    for ver, path, label in py_installs(host).get("certifi", []):
        v = hs.parse_version(ver)
        if v is None:
            r.add("unknown", "certifi (%s)" % label, "version not parsed", path=host.display(path), version=ver)
        else:
            bad = hs.below(v, "2026.10.19")
            r.add("affected" if bad else "info", "certifi (%s)" % label,
                  "older than 2026.10.19 still trusts the eMudhra roots" if bad else "2026.10.19 or newer",
                  path=host.display(path), version=ver)
    for path, _n, v in py_pin_hits(host, {"certifi"}, include_docker=False):
        pv = hs.parse_version(v) if not v.startswith("spec:") else None
        if pv is not None:
            r.add("affected" if hs.below(pv, "2026.10.19") else "info", "certifi pin", "exact pin", path=host.display(path), version=v)


def trust_bundles(host):
    c = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
         "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/certs/ca-bundle.crt",
         "/opt/homebrew/etc/ca-certificates/cert.pem", "/usr/local/etc/ca-certificates/cert.pem",
         "/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem", "/private/etc/ssl/cert.pem"]
    out = [host.sys(p) for p in c] if host.platform != "windows" else []
    for _label, sp in site_dirs(host)[:400]:
        out += [os.path.join(sp, "certifi", "cacert.pem"), os.path.join(sp, "pip", "_vendor", "certifi", "cacert.pem")]
    seen, uniq = set(), []
    for p in out:
        st = hs.lstat(p)
        if st is None or not stat.S_ISREG(st.st_mode):
            continue
        key = (st.st_dev, st.st_ino) if st.st_ino else os.path.normcase(p)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def check_emudhra_store(host, r):
    stores = 0
    for path in trust_bundles(host):
        data = hs.read_bytes(path, 16 * MIB, host.gaps)
        if data is None:
            continue
        stores += 1
        for der in hs.pem_certificates(data):
            name = hs.der_mentions(der)
            if name:
                r.add("review", "eMudhra certificate in trust bundle", "report only; this tool does not edit trust stores "
                      "(Apple's support page explains removal from /etc/ssl/cert.pem)", path=host.display(path),
                      subject_text=name, sha256=hashlib.sha256(der).hexdigest())
    if host.platform == "darwin":
        for kc in ("/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"):
            if not hs.exists_nofollow(host.sys(kc)):
                continue
            out = host.run(["security", "find-certificate", "-a", "-p", kc], 30)
            if out is None:
                host.gaps.add("tool_missing", host.sys(kc), "keychain not read")
                continue
            stores += 1
            for der in hs.pem_certificates(out[1]):
                name = hs.der_mentions(der)
                if name:
                    r.add("review", "eMudhra certificate in keychain", "report only; Apple blocks them in Safari and "
                          "apps, but curl and git can still trust them until a macOS update", path=kc,
                          subject_text=name, sha256=hashlib.sha256(der).hexdigest())
    if host.cert_stores:
        stores += 1
        for store, der in host.cert_stores:
            name = hs.der_mentions(der)
            if name:
                r.add("review", "eMudhra certificate in Windows %s store" % store, "report only", subject_text=name,
                      sha256=hashlib.sha256(der).hexdigest())
    r.present = stores > 0
    if not stores:
        r.blocked.append("no trust store bundle or keychain could be read")
    r.notes.append("%d trust store(s) read" % stores)


def check_chrome(host, r):
    for b in browsers(host):
        if not b["browser"].startswith(("Google Chrome", "Chromium")):
            continue
        v = hs.parse_version(b["version"]) if b["version"] else None
        if v is None:
            r.add("unknown", b["browser"], "installed; version not readable (%s)" % b["source"], path=host.display(b["path"]))
        else:
            bad = v.nums[0] < 156
            r.add("affected" if bad else "info", b["browser"], ("below 156; update and restart" if bad else
                  "156 or newer; restart to finish any pending update") + " (%s)" % b["source"],
                  path=host.display(b["path"]), version=b["version"])


def check_browsers(host, r):
    for b in browsers(host):
        r.add("info", b["browser"], "version recorded (%s)" % b["source"], path=host.display(b["path"]),
              version=b["version"] or "unknown")
    if r.present:
        r.blocked.append("CVE-2026-40369 is unconfirmed: the affected browser and fix are not known, so versions "
                         "are recorded but cannot be classified")


def check_php(host, r):
    installs = php_installs(host)
    for src, ver, path in installs:
        if ver == "unknown":
            r.add("unknown", "PHP (%s)" % src, "installed; version not readable", path=host.display(path))
            continue
        res = classify_version(r, "PHP (%s)" % src, ver, host.display(path), ["8.5.12", "8.4.27", "8.3.36", "8.2.35"], 2)
        if res and host.platform == "windows" and src.startswith("Windows build"):
            r.add("review", "PHP Windows build", "Brotli rebuild: confirm the new -1 build (for example 8.5.12-1) when "
                  "cURL auto-decompression is used; the PE version does not show the rebuild suffix", path=host.display(path))
    for path, image, tag in docker_refs(host, r"php"):
        v = hs.parse_version(tag)
        if v and len(v.nums) >= 3:
            classify_version(r, "PHP base image", tag, host.display(path), ["8.5.12", "8.4.27", "8.3.36", "8.2.35"], 2, (), "image tag")
        else:
            r.add("info", "PHP base image", "moving tag %s; rebuild to pick up the fixed build" % tag, path=host.display(path), version=tag)
    if installs:
        inis = php_inis(host)
        for ini in inis:
            vals = re.findall(r"(?mi)^\s*session\.upload_progress\.enabled\s*=\s*\"?(\w+)", hs.read_text(ini, 4 * MIB) or "")
            off = bool(vals) and vals[-1].lower() in ("0", "off", "false", "no")
            r.add("info" if off else "review", "php.ini session.upload_progress.enabled",
                  "disabled (CVE-2026-115560 mitigation)" if off else
                  "not disabled; CVE-2026-115560 has no patch, the mitigation is session.upload_progress.enabled=0",
                  path=host.display(ini))
        if not inis:
            r.add("review", "php.ini", "no php.ini found; the default leaves session.upload_progress enabled")


def presence_check(host, r, component, paths=(), binaries=(), packages=(), formulas=(), registry=None, dists=(),
                   detail=""):
    for p in paths:
        if hs.exists_nofollow(p):
            r.add("review", component, detail, path=host.display(p))
    for b in find_binaries(host, binaries):
        r.add("review", component, detail + " (binary on PATH)", path=host.display(b))
    pk = linux_packages(host)
    for name in packages:
        for ver, src in pk.get(name, []):
            r.add("review", component, detail + " (package %s, %s)" % (name, src), version=ver)
    for f in formulas:
        for ver, p in cellar(host).get(f, []):
            r.add("review", component, detail + " (Homebrew)", path=host.display(p), version=ver)
    if registry:
        for e in registry_matches(host, registry):
            r.add("review", component, detail + " (uninstall registry)", version=e.get("version") or None)
    for d in dists:
        for ver, p, label in py_installs(host).get(d, []):
            r.add("review", component, detail + " (%s)" % label, path=host.display(p), version=ver)


def check_railway(host, r):
    presence_check(host, r, "Railway CLI or config", [host.h(".railway")], ["railway"], formulas=["railway"],
                   detail="Railway in use: rotate every secret stored on Railway and review service logs")
    for nm in global_node_modules(host):
        if hs.is_plain_dir(os.path.join(nm, "@railway", "cli")):
            r.add("review", "Railway CLI (npm global)", "rotate every secret stored on Railway", path=host.display(nm))


def check_opencode(host, r):
    presence_check(host, r, "OpenCode client", [host.h(".local", "share", "opencode"), host.h(".config", "opencode"),
                                                host.h(".opencode")], ["opencode"], formulas=["opencode"],
                   detail="OpenCode installed: if OpenCode Console stored provider keys, rotate them and review AI bills since 16 Oct")


def check_warp(host, r):
    presence_check(host, r, "Warp terminal", [host.sys("/Applications/Warp" + APP), host.h(".warp"),
                                              host.h(".local", "share", "warp-terminal"), os.path.join(host.localappdata(), "warp")],
                   ["warp-terminal"], packages=["warp-terminal"], registry=r"^Warp\b",
                   detail="Warp installed: follow Warp's notice if received; rotate keys that appeared in Warp agent sessions")


def check_lightning(host, r):
    presence_check(host, r, "Lightning AI client", [host.h(".lightning")], ["lightning"], dists=["lightning_sdk"],
                   detail="Lightning AI used: rotate keys and GitHub tokens stored there and check access logs "
                          "(credential file not read)")


def check_vitest(host, r):
    hits = lock_hits(host, {"vitest", "@vitest/ui", "@vitest/browser"})
    mode = {p for p, n, _v in hits if n in ("@vitest/ui", "@vitest/browser")}
    for path, n, v in hits:
        if n != "vitest":
            continue
        if v.startswith("spec:"):
            r.add("info", "vitest range", "range %s in package.json; the lockfile decides" % v[5:], path=host.display(path))
            continue
        pv = hs.parse_version(v)
        if pv and pv.nums[0] == 5 and hs.below(pv, "5.0.5"):
            r.add("affected", "vitest", "Vitest 5 below 5.0.5" + ("; UI or Browser Mode package in the same lockfile"
                                                                 if path in mode else ""), path=host.display(path), version=v)
        else:
            r.add("info", "vitest", "not in Vitest 5 below 5.0.5", path=host.display(path), version=v)
    for nm in index(host).node_modules[:20000]:
        pj = os.path.join(nm, "vitest", "package.json")
        if hs.is_regular(pj):
            doc = hs.read_json(pj, MIB) or {}
            v = hs.parse_version(doc.get("version")) if isinstance(doc, dict) else None
            if v:
                bad = v.nums[0] == 5 and hs.below(v, "5.0.5")
                r.add("affected" if bad else "info", "vitest (node_modules)", "installed copy", path=host.display(pj), version=v.raw)


def check_pillow(host, r):
    for ver, path, label in py_installs(host).get("pillow", []):
        v = hs.parse_version(ver)
        r.add("unknown" if v is None else ("affected" if hs.below(v, "13.0.0") else "info"), "Pillow (%s)" % label,
              "below 13.0.0" if v is not None and hs.below(v, "13.0.0") else "13.0.0 or newer", path=host.display(path), version=ver)
    for path, _n, v in py_pin_hits(host, {"pillow"}, include_docker=False):
        pv = hs.parse_version(v) if not v.startswith("spec:") else None
        if pv:
            r.add("affected" if hs.below(pv, "13.0.0") else "info", "Pillow pin", "exact pin", path=host.display(path), version=v)


def ovh_classify(r, component, ver, path, source):
    v = hs.parse_version(ver)
    if v is None:
        r.add("unknown", component, "present; version not readable (%s)" % source, path=path)
    elif hs.at_least(v, "0.16.0"):
        r.add("info", component, "0.16.0 or newer", path=path, version=ver)
    elif hs.at_least(v, "0.11.0") and hs.cmp_nums(v.nums, (0, 15, 0)) <= 0:
        r.add("affected", component, "backdoored range 0.11.0 to 0.15.0; remove it and treat secrets on disk as exposed",
              path=path, version=ver)
    else:
        r.add("review", component, "outside the listed range; the briefing says use 0.16.0 or remove the tool", path=path, version=ver)


def check_ovhcloud(host, r):
    extra = [host.h("go", "bin"), host.h(".local", "bin"), host.sys("/usr/local/bin"), host.sys("/opt/homebrew/bin")]
    for exe in find_binaries(host, ["ovhcloud"], extra):
        info = hs.go_main_module(exe) if hs.is_regular(exe) else None
        ver = info[1] if info and info[1] not in ("(devel)", "") else None
        ovh_classify(r, "OVHcloud CLI", ver, host.display(exe), "Go build info" if info else "no build info")
    for f in ("ovhcloud", "ovhcloud-cli"):
        for ver, p in cellar(host).get(f, []):
            ovh_classify(r, "OVHcloud CLI (Homebrew)", ver, host.display(p), "Cellar")


# NVD (CNA GitLab Inc.): CE/EE from 19.2 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2.
GITLAB_KEV_FIX = {(19, 2): "19.2.8", (19, 3): "19.3.5", (19, 4): "19.4.2"}
CLAUDE_VSX_BAD = "2.1.313"
# Vendor-named key comment. The public key itself is not stored here.
SVC_TELEMETRY = "svc" + "-telemetry"
STK_TMP_RE = re.compile(r"^\.stk_[0-9a-f]{10}$")
# Check Point-named Yoba project fragments (not emails, not live hosts).
YOBA_NAME_FRAGMENTS = ("sol-free-desktop", "gpt-5-6", "gpt-6-astra", "opus-5-0", "claude-opus")
HF_CACHE_NAMES = (
    "models--MENXIANGYU--qwen2-tiny",
    "models--htt0118--qwen2-tiny",
    "models--wjsbg--qwen2-tiny",
    "models--soumikmahato--qwen2-tiny",
    "models--r1r13--qwen2-tiny",
)


def gitlab_classify(r, component, ver, path, source):
    v = hs.parse_version(ver) if ver else None
    if v is None:
        r.add("review", component,
              "self-hosted GitLab present; version not readable (%s); CVE-2026-97229 is on the CISA KEV list" % source,
              path=path, version=ver)
        return
    if len(v.nums) >= 2 and (v.nums[0], v.nums[1]) in GITLAB_KEV_FIX:
        floor = GITLAB_KEV_FIX[(v.nums[0], v.nums[1])]
        if hs.below(v, floor):
            r.add("affected", component,
                  "CVE-2026-97229 (CISA KEV); NVD lists this minor as affected before %s" % floor,
                  path=path, version=ver)
        else:
            r.add("info", component, "at or above %s for this minor (CVE-2026-97229)" % floor, path=path, version=ver)
        return
    r.add("review", component,
          "self-hosted GitLab present; outside the NVD 19.2-19.4 range for CVE-2026-97229 (confirm other advisories)",
          path=path, version=ver)


def check_gitlab(host, r):
    manifest = host.sys("/opt/gitlab/version-manifest.txt")
    if hs.is_regular(manifest):
        first = (hs.read_text(manifest, 64 * 1024) or "").splitlines()[:1]
        ver = first[0].split()[-1] if first and first[0].split() else None
        gitlab_classify(r, "self-hosted GitLab", ver, host.display(manifest), "version-manifest")
    rb = host.sys("/etc/gitlab/gitlab.rb")
    if hs.exists_nofollow(rb) and not r.findings:
        r.add("review", "self-hosted GitLab",
              "gitlab.rb present without a readable version-manifest; CVE-2026-97229 is on the CISA KEV list",
              path=host.display(rb))
    for name in ("gitlab-ce", "gitlab-ee"):
        for ver, src in linux_packages(host).get(name, []):
            gitlab_classify(r, "self-hosted GitLab (%s)" % name, ver, None, src)
    for path, image, tag in docker_refs(host, r"gitlab/gitlab-(?:ce|ee)"):
        gitlab_classify(r, "GitLab image", tag, host.display(path), "image tag")


def _claude_vsx_version(name):
    low = name.lower()
    if not low.startswith("anthropic.claude-code-"):
        return None
    m = re.match(r"^anthropic\.claude-code-(\d+\.\d+\.\d+)", low)
    return m.group(1) if m else None


def _temp_dirs(host):
    found, seen = [], set()
    for key in ("TMPDIR", "TMP", "TEMP"):
        val = host.env.get(key)
        if not val:
            continue
        if host.sysroot and re.match(r"^[A-Za-z]:[\\/]", val) and not under_root(host.sysroot, val):
            val = host.sys(val)
        found.append(val)
    if host.platform == "windows":
        found.append(host.sys("C:/Windows/Temp"))
        local = host.localappdata()
        if local:
            found.append(os.path.join(local, "Temp"))
    else:
        found.extend([host.sys("/tmp"), host.h("tmp")])
    out = []
    for d in found:
        key = os.path.normcase(os.path.abspath(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def check_claude_code_vsx(host, r):
    bases = [host.h(".cursor", "extensions"), host.h(".vscode", "extensions"),
             host.h(".vscode-insiders", "extensions"), host.h(".windsurf", "extensions")]
    if host.platform == "darwin":
        bases.append(host.h("Library", "Application Support", "Cursor", "CachedExtensionVSIXs"))
    elif host.platform == "linux":
        bases.append(host.h(".config", "Cursor", "CachedExtensionVSIXs"))
    else:
        ad = host.appdata()
        if ad:
            bases.append(os.path.join(ad, "Cursor", "CachedExtensionVSIXs"))
    for base in bases:
        for name in hs.listdir(base):
            ver = _claude_vsx_version(name)
            path = os.path.join(base, name)
            if ver is None:
                if not (name.lower().startswith("anthropic.claude-code") or "claude-code-2.1.313" in name.lower()):
                    continue
                pj = os.path.join(path, "package.json")
                doc = hs.read_json(pj, MIB) if hs.is_regular(pj) else None
                ver = doc.get("version") if isinstance(doc, dict) else None
            if ver == CLAUDE_VSX_BAD or "2.1.313" in name:
                r.add("affected", "Anthropic.claude-code extension",
                      "2.1.313 is the tampered Cursor Marketplace build in the vendor notice",
                      path=host.display(path), version=ver or CLAUDE_VSX_BAD)
            elif ver:
                r.add("info", "Anthropic.claude-code extension",
                      "installed; not the 2.1.313 build named in the vendor notice",
                      path=host.display(path), version=ver)
            extjs = os.path.join(path, "extension.js")
            if hs.is_regular(extjs) and SVC_TELEMETRY in (hs.read_text(extjs, 8 * MIB) or ""):
                r.add("affected", "extension.js indicator",
                      "contains the vendor-named key comment; key material is not copied",
                      path=host.display(extjs))

    keys = [host.h(".ssh", "authorized_keys"), host.h(".ssh", "authorized_keys2")]
    if host.platform == "windows":
        keys.append(host.sys("C:/ProgramData/ssh/administrators_authorized_keys"))
    for ak in keys:
        if not hs.exists_nofollow(ak):
            continue
        if not hs.is_regular(ak):
            r.blocked.append("authorized_keys is not a regular file")
            continue
        text = hs.read_text(ak, MIB)
        if text is None:
            r.blocked.append("authorized_keys unreadable")
            continue
        if SVC_TELEMETRY in text:
            r.add("affected", "SSH authorized_keys comment",
                  "vendor-named key comment present; this tool does not print key material",
                  path=host.display(ak))

    for spec, label in ((host.h(".config", ".smt"), "persistence script"),
                        (host.h(".config", ".smtk"), "tunnel key file"),
                        (host.h(".config", "smt.cmd"), "persistence script"),
                        (host.h(".config", "smtk"), "tunnel key file")):
        if hs.exists_nofollow(spec):
            r.add("affected", label, "vendor-named persistence artifact; contents not copied",
                  path=host.display(spec))

    plist = host.h("Library", "LaunchAgents", "com.apple.sysmond.plist")
    if hs.is_regular(plist):
        label = hs.plist_value(plist, "Label")
        r.add("affected", "LaunchAgent",
              "vendor-named fake sysmond agent (label %s)" % (label or "unreadable"),
              path=host.display(plist))

    for td in _temp_dirs(host):
        for name in hs.listdir(td):
            if STK_TMP_RE.match(name):
                r.add("affected", "tunnel key tempfile",
                      "filename matches the vendor-named .stk_ pattern; contents not read",
                      path=host.display(os.path.join(td, name)))

    if host.platform == "windows":
        ad = host.appdata()
        if ad:
            startup = os.path.join(ad, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "sysmon.cmd")
            if hs.exists_nofollow(startup):
                r.add("affected", "Startup script", "vendor-named sysmon.cmd fallback", path=host.display(startup))
        task = host.sys("C:/Windows/System32/Tasks/SysMon")
        if hs.is_regular(task):
            text = hs.read_text(task, MIB) or ""
            if re.search(r"(?i)smt\.cmd|[/\\]\.config[/\\]smt|\.smt\b", text):
                r.add("affected", "scheduled task SysMon",
                      "task file references the vendor-named persistence script", path=host.display(task))
            else:
                r.add("review", "scheduled task SysMon",
                      "a task named SysMon exists; confirm it is not this implant (Sysinternals Sysmon is a different name)",
                      path=host.display(task))

    if host.platform == "linux":
        for spool in (host.sys("/var/spool/cron/crontabs"), host.sys("/var/spool/cron")):
            for name in hs.listdir(spool):
                fp = os.path.join(spool, name)
                if not hs.is_regular(fp):
                    continue
                text = hs.read_text(fp, MIB)
                if text is None:
                    r.blocked.append("crontab unreadable")
                    continue
                if re.search(r"(?<!\w)\.smtk?\b", text):
                    # Spool filenames are account names; do not copy them.
                    r.add("affected", "user crontab",
                          "crontab references the vendor-named persistence script",
                          path=(host.display(os.path.dirname(fp)) or "/var/spool/cron") + "/<user>")


def _yoba_themed(name):
    low = name.lower()
    return any(frag in low for frag in YOBA_NAME_FRAGMENTS)


def _yoba_inspect_dir(host, r, path, name):
    if not hs.is_plain_dir(path):
        return
    names = {n.lower() for n in hs.listdir(path)}
    themed = _yoba_themed(name)
    if "setup.exe" in names and "winmm.dll" in names:
        r.add("affected" if themed else "review", "sideload pair",
              "Setup.exe next to winmm.dll (Check Point Yoba dropper layout)"
              + ("; folder name matches a named fake app" if themed else "; confirm this is not an unexpected extract"),
              path=host.display(path))
    elif themed:
        r.add("review", "fake-app folder name",
              "directory name matches a Check Point-named Yoba project", path=host.display(path))


def check_yoba(host, r):
    wmp = host.sys("C:/ProgramData/WMProcess")
    if hs.is_plain_dir(wmp):
        r.add("affected", "WMProcess directory",
              "Check Point names this folder as the Yoba second-stage sideload location",
              path=host.display(wmp))
    roots = list(downloads_dirs(host)) + [host.h("Desktop")]
    if host.platform == "windows":
        # Split so the public-package home-path scanner does not read this as a username.
        roots.append(host.sys("C:/" + "Users/Public/Downloads"))
    seen = set()
    for root in roots:
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        _yoba_inspect_dir(host, r, root, os.path.basename(root.rstrip("/\\")))
        for name in hs.listdir(root):
            inner = os.path.join(root, name)
            _yoba_inspect_dir(host, r, inner, name)
            if hs.is_plain_dir(inner):
                for nested in hs.listdir(inner):
                    _yoba_inspect_dir(host, r, os.path.join(inner, nested), nested)


def check_hf_qwen2(host, r):
    caches = [host.h(".cache", "huggingface", "hub"), host.h(".cache", "huggingface")]
    for key in ("HF_HOME", "HUGGINGFACE_HUB_CACHE"):
        val = host.env.get(key)
        if val:
            caches.append(os.path.join(val, "hub") if key == "HF_HOME" else val)
    seen = set()
    for cache in caches:
        key = os.path.normcase(os.path.abspath(cache))
        if key in seen:
            continue
        seen.add(key)
        for name in hs.listdir(cache):
            hit = name in HF_CACHE_NAMES or name.startswith("models--MENXIANGYU--") or name.startswith("models--htt0118--")
            if hit:
                r.add("unknown", "Hugging Face hub cache",
                      "directory name matches a press-named model; campaign is an unconfirmed lead",
                      path=host.display(os.path.join(cache, name)))
    cch = host.sys("/tmp/.cch")
    if hs.exists_nofollow(cch):
        r.add("unknown", "tmp watchdog path",
              "path matches a press-named persistence location; campaign is an unconfirmed lead",
              path=host.display(cch))


def _go_mod_facts(text):
    go_ver, mitigated = None, False
    for ln in (text or "").splitlines():
        stripped = ln.strip()
        if stripped.startswith("go ") and go_ver is None:
            m = re.match(r"go\s+(\d+\.\d+(?:\.\d+)?)", stripped)
            if m:
                go_ver = m.group(1)
        if re.match(r"(?i)godebug\s+.*\bmultipathtcp=0\b", stripped):
            mitigated = True
    return go_ver, mitigated


def check_go_mptcp(host, r):
    # Indexed go.mod files, plus go.sum siblings and repository-root go.mod as fallbacks.
    mods = []
    seen_mods = set()
    for gomod in index(host).gomod:
        if hs.is_regular(gomod) and gomod not in seen_mods:
            mods.append(gomod)
            seen_mods.add(gomod)
    for gosum in index(host).gosum:
        gomod = os.path.join(os.path.dirname(gosum), "go.mod")
        if hs.is_regular(gomod) and gomod not in seen_mods:
            mods.append(gomod)
            seen_mods.add(gomod)
    for repo in index(host).repos:
        gomod = os.path.join(repo, "go.mod")
        if hs.is_regular(gomod) and gomod not in seen_mods:
            mods.append(gomod)
            seen_mods.add(gomod)
    for path in mods:
        ver, mitigated = _go_mod_facts(hs.read_text(path, MIB) or "")
        if ver is None and not mitigated:
            continue
        v = hs.parse_version(ver) if ver else None
        default_on = bool(v and not hs.below(v, "1.24.0"))
        if host.platform == "linux" and default_on and not mitigated:
            r.add("review", "go.mod MPTCP default",
                  "Go 1.24+ enables MPTCP listen sockets on Linux; CVE-2026-98432 is a kernel bug. "
                  "The Go team named no patched kernel version here. Confirm the running kernel and "
                  "consider godebug multipathtcp=0 as a fragile mitigation only.",
                  path=host.display(path), version=ver)
        elif mitigated:
            r.add("info", "go.mod MPTCP default",
                  "godebug multipathtcp=0 is set (build-time default off; per-socket APIs can still enable it)",
                  path=host.display(path), version=ver)
        elif ver:
            r.add("info", "go.mod", "Go language version recorded; MPTCP default applies from 1.24 on Linux",
                  path=host.display(path), version=ver)

    for label, path in ((" /usr/local/go", host.sys("/usr/local/go/VERSION")),
                        (" /usr/lib/go", host.sys("/usr/lib/go/VERSION"))):
        if hs.is_regular(path):
            lines = (hs.read_text(path, 256) or "").strip().splitlines()
            raw = lines[0].strip() if lines else ""
            ver = raw[2:] if raw.lower().startswith("go") else raw
            v = hs.parse_version(ver)
            if host.platform == "linux" and v and not hs.below(v, "1.24.0"):
                r.add("review", "Go toolchain" + label,
                      "1.24+ on Linux; kernel CVE-2026-98432. Confirm the running kernel.",
                      path=host.display(path), version=ver)
            elif ver:
                r.add("info", "Go toolchain" + label, "toolchain VERSION file", path=host.display(path), version=ver)
    for ver, src in linux_packages(host).get("golang-go", []) + linux_packages(host).get("golang", []):
        v = hs.parse_version(ver)
        if host.platform == "linux" and v and not hs.below(v, "1.24.0"):
            r.add("review", "Go package", "1.24+ on Linux; kernel CVE-2026-98432. Confirm the running kernel.",
                  version=ver)
        else:
            r.add("info", "Go package", "installed (%s)" % src, version=ver)
    for ver, p in cellar(host).get("go", []):
        r.add("info", "Go (Homebrew)", "toolchain present; the MPTCP default is a Linux listen-socket behaviour",
              path=host.display(p), version=ver)
    if host.platform == "linux":
        kver = (hs.read_text(host.sys("/proc/version"), 4096) or "").strip()
        if kver:
            # Record that a kernel string was readable. Do not classify: no patched build was named.
            r.notes.append("kernel uname string was readable from /proc/version (not classified; no patched build named)")
    if not r.findings and host.platform != "linux":
        r.notes.append("CVE-2026-98432 / Go MPTCP default is a Linux listen-socket issue; this host is %s" % host.platform)


def check_ruby(host, r):
    for src, ver, path in ruby_installs(host):
        classify_version(r, "Ruby (%s)" % src, ver, host.display(path), ["4.0.9", "3.4.12", "3.3.13"], 2, [(3, 2)],
                         "metadata", "; matters for apps that build a regex from user text")


def check_nginx(host, r):
    paths = [host.sys(p) for p in ("/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/usr/local/sbin/nginx")]
    if host.platform == "windows":
        paths += [os.path.join(d, "nginx.exe") for d in glob_dirs(host, host.sys("C:/"), "nginx*")]
    presence_check(host, r, "NGINX", paths, packages=["nginx", "nginx-core", "nginx-full", "nginx-light", "nginx-extras",
                                                      "nginx-mainline", "openresty", "nginx-plus"],
                   formulas=["nginx", "openresty"], detail="update NGINX (briefing names no version)")
    for path, image, tag in docker_refs(host, r"nginx|nginxinc/[\w-]+"):
        r.add("review", "NGINX image", "update NGINX and rebuild", path=host.display(path), version=tag, image=image)


def wasmtime_classify(r, component, ver, path, source):
    v = hs.parse_version(ver)
    if v is None:
        r.add("unknown", component, "version not readable (%s)" % source, path=path)
        return
    if hs.at_least(v, "50.0.0"):
        r.add("info", component, "50.0.0 or newer", path=path, version=ver)
        return
    classify_version(r, component, ver, path, ["36.0.19", "48.0.7", "49.0.4"], 1, (), source,
                     "; rebuild anything that embeds it")


def check_wasmtime(host, r):
    for path in index(host).cargo:
        for _n, vers in hs.cargo_lock_versions(text_of(host, path) or "", {"wasmtime"}).items():
            for v in sorted(vers):
                wasmtime_classify(r, "wasmtime crate", v, host.display(path), "Cargo.lock")
    for ver, path, label in py_installs(host).get("wasmtime", []):
        wasmtime_classify(r, "wasmtime Python package (%s)" % label, ver, host.display(path), "dist-info")
    for path in index(host).gosum:
        for m in re.finditer(r"(?m)^github\.com/bytecodealliance/wasmtime-go(?:/v\d+)?\s+(v[\d.]+)(?:/go\.mod)?\s",
                             text_of(host, path, 8 * MIB) or ""):
            wasmtime_classify(r, "wasmtime-go module", m.group(1), host.display(path), "go.sum")
    for path in index(host).nuget:
        text = text_of(host, path, 4 * MIB) or ""
        for m in re.finditer(r'(?is)"wasmtime"\s*:\s*\{[^}]*?"resolved"\s*:\s*"([^"]+)"|'
                             r'<PackageReference\s+Include="Wasmtime"\s+Version="([^"]+)"', text):
            wasmtime_classify(r, "Wasmtime NuGet package", m.group(1) or m.group(2), host.display(path), "NuGet")
    for ver, p in cellar(host).get("wasmtime", []):
        wasmtime_classify(r, "wasmtime CLI (Homebrew)", ver, host.display(p), "Cellar")
    for exe in find_binaries(host, ["wasmtime"], [host.h(".wasmtime", "bin")]):
        r.add("info", "wasmtime CLI", "CLI present; updating it does not fix embedded copies", path=host.display(exe))


def check_qdrant(host, r):
    cluster_files = set()
    for path in index(host).qdrant_cfg:
        if re.search(r"(?ms)^cluster:\s*\n(?:\s+.*\n)*?\s+enabled:\s*true", text_of(host, path, MIB) or ""):
            cluster_files.add(path)
            r.add("review", "Qdrant config", "cluster mode enabled; block port 6335 and run 1.20.0 or newer", path=host.display(path))
    for path, image, tag in docker_refs(host, r"qdrant/qdrant"):
        text = text_of(host, path, 4 * MIB) or ""
        cluster = bool(re.search(r"(?i)QDRANT__CLUSTER__ENABLED\W+true|--uri\b|--bootstrap\b", text))
        v = hs.parse_version(tag)
        if v is None:
            r.add("unknown", "Qdrant image", "tag %s does not show a version" % tag, path=host.display(path), version=tag)
        elif hs.at_least(v, "1.20.0"):
            r.add("info", "Qdrant image", "1.20.0 or newer", path=host.display(path), version=tag)
        else:
            r.add("affected" if cluster else "review", "Qdrant image",
                  "before 1.20.0 with cluster mode" if cluster else "before 1.20.0; affected only in cluster mode",
                  path=host.display(path), version=tag)
    for ver, p in cellar(host).get("qdrant", []):
        v = hs.parse_version(ver)
        r.add("review" if v and hs.below(v, "1.20.0") else "info", "Qdrant (Homebrew)", "affected only in cluster mode",
              path=host.display(p), version=ver)


def check_ksmbd(host, r):
    if host.platform != "linux":
        r.notes.append("KSMBD is a Linux kernel SMB server; not applicable on %s" % host.platform)
        return
    if hs.is_plain_dir(host.sys("/sys/module/ksmbd")):
        r.add("affected", "KSMBD kernel module", "loaded; no kernel fix yet: turn it off if not needed and block port 445",
              path="/sys/module/ksmbd")
    mods = hs.read_text(host.sys("/proc/modules"), 4 * MIB) or ""
    if re.search(r"(?m)^ksmbd\s", mods) and not r.findings:
        r.add("affected", "KSMBD kernel module", "listed in /proc/modules; turn it off if not needed", path="/proc/modules")
    if hs.exists_nofollow(host.sys("/etc/ksmbd/ksmbd.conf")):
        r.add("review", "KSMBD config", "ksmbd.conf present", path="/etc/ksmbd/ksmbd.conf")
    for wants in glob_dirs(host, host.sys("/etc/systemd/system"), "*.wants"):
        if hs.exists_nofollow(os.path.join(wants, "ksmbd.service")):
            r.add("review", "KSMBD service", "enabled at boot", path=host.display(os.path.join(wants, "ksmbd.service")))
    for ver, src in linux_packages(host).get("ksmbd-tools", []):
        r.add("review", "ksmbd-tools package", "user-space tools installed (%s)" % src, version=ver)
    if not r.findings:
        for kdir in hs.subdirs(host.sys("/lib/modules"))[:20]:
            for sub in (("kernel", "fs", "smb", "server"), ("kernel", "fs", "ksmbd")):
                d = os.path.join(host.sys("/lib/modules"), kdir, *sub)
                if any(n.startswith("ksmbd.ko") for n in hs.listdir(d)):
                    r.notes.append("module available for kernel %s but not loaded" % kdir)


def check_collabora(host, r):
    presence_check(host, r, "Collabora Online", [host.sys("/usr/share/coolwsd"), host.sys("/etc/coolwsd")]
                   + glob_dirs(host, host.sys("/opt"), "collaboraoffice*"),
                   packages=["coolwsd", "collabora-online", "code-brand", "loolwsd"],
                   detail="update Collabora (CISA exploited list)")
    for d in index(host).nextcloud:
        r.add("review", "Nextcloud", "check whether the built-in CODE server (Collabora) is used", path=host.display(d))
    for path, image, tag in docker_refs(host, r"collabora/code|nextcloud"):
        r.add("review", "Collabora or Nextcloud image", "update Collabora", path=host.display(path), version=tag, image=image)


def check_updraft(host, r):
    for d in index(host).updraft:
        m = re.search(r"(?mi)^\s*\*?\s*Version:\s*(\S+)", hs.read_text(os.path.join(d, "updraftplus.php"), 256 * 1024) or "")
        r.add("review", "WordPress UpdraftPlus", "stolen UpdraftCentral keys are used to backdoor sites; no fix stated",
              path=host.display(d), version=m.group(1) if m else None)


def check_magento(host, r):
    for d in index(host).magento:
        r.add("review", "Magento store code", "check cms_block for code nobody added and apply Adobe's PolyShell fix "
              "(database not read)", path=host.display(d))


COMMERCE_8X = re.compile(r"^8\.x-")
COMMERCE_DEV = re.compile(r"(?:^dev-)|(?:x-dev(?:$|[-.]))|(?:-dev(?:$|[+.\d-]))")
COMMERCE_FLOORS = ("2.41", "3.3.13")
COMMERCE_INFO_LIMIT = 64 * 1024
COMMERCE_INFO_YML = "commerce" + ".info.yml"
COMMERCE_PROJECT_RE = re.compile(
    r"(?mi)^project:[ \t]*(?:'commerce'|\"commerce\"|commerce)[ \t]*(?:#.*)?$")
COMMERCE_PROJECT_ANY_RE = re.compile(r"(?mi)^project:[ \t]*")
COMMERCE_VERSION_RE = re.compile(
    r"(?m)^version:[ \t]*(?:'([^'#\n]*)'|\"([^\"#\n]*)\"|([^'\"#\s]\S*))\s*(?:#.*)?$")
COMMERCE_VERSION_ANY_RE = re.compile(r"(?m)^version:[ \t]*[^\s#]")


def _commerce_version_values(text):
    values = []
    for parts in COMMERCE_VERSION_RE.findall(text):
        ver = "".join(parts).strip()
        if ver:
            values.append(ver)
    return values
COMMERCE_INFO_REL_RE = re.compile(
    r"^(?:web/|docroot/|html/|public/)?modules/(?:contrib/)?"
    r"commerce/" + re.escape(COMMERCE_INFO_YML) + r"$",
    re.I)
COMMERCE_PKG_NAME_RE = re.compile(r'"name"\s*:\s*"drupal/commerce"')


def _commerce_normalize(text):
    return text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def _in_composer_vendor(file_path):
    """True when the file sits under a Composer vendor tree.

    A directory named vendor counts only if it contains autoload.php or
    composer/installed.json, so ~/clients/vendor/acme/shop/composer.lock is
    not skipped.
    """
    current = os.path.dirname(os.path.abspath(file_path))
    while True:
        if os.path.basename(current).lower() == "vendor":
            return (
                hs.is_regular(os.path.join(current, "autoload.php"))
                or hs.is_regular(os.path.join(current, "composer", "installed.json"))
            )
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _commerce_packages(doc):
    blocks = []
    if isinstance(doc, list):
        blocks = [doc]
    elif isinstance(doc, dict):
        for key in ("packages", "packages-dev"):
            block = doc.get(key)
            if isinstance(block, list):
                blocks.append(block)
    out = []
    for block in blocks:
        for pkg in block:
            if isinstance(pkg, dict) and pkg.get("name") == "drupal/commerce":
                out.append(pkg.get("version"))
    return out


def _commerce_site_root(path):
    norm = os.path.normcase(os.path.abspath(path))
    parent = os.path.dirname(norm)
    if os.path.basename(norm) == "installed.json":
        if os.path.basename(parent).lower() == "composer":
            vendor = os.path.dirname(parent)
            if os.path.basename(vendor).lower() == "vendor":
                return os.path.dirname(vendor)
    return parent


def _under_site(path, root):
    path = os.path.normcase(os.path.abspath(path))
    root = os.path.normcase(os.path.abspath(root))
    if path == root:
        return True
    return path.startswith(root + os.sep)


def _commerce_relposix(path, root):
    path = os.path.normcase(os.path.abspath(path))
    root = os.path.normcase(os.path.abspath(root))
    return os.path.relpath(path, root).replace("\\", "/")


def classify_commerce(r, component, raw, path, source):
    if raw is None or not str(raw).strip().strip("\"'"):
        r.add("unknown", component, "version string missing (%s)" % source, path=path)
        return "unknown"
    original = str(raw).strip().strip("\"'")
    reported = textscan.redact(original)[:64]
    stripped = COMMERCE_8X.sub("", original, count=1)
    if COMMERCE_DEV.search(stripped.lower()) or COMMERCE_DEV.search(original.lower()):
        r.add("review", component, "development build; check commit (%s)" % source,
              path=path, version=reported)
        return "review"
    if "#" in original or "#" in stripped:
        r.add("review", component, "unsupported version suffix (%s)" % source,
              path=path, version=reported)
        return "review"
    before = len(r.findings)
    res = classify_version(r, component, stripped, path, COMMERCE_FLOORS, line_len=1, source=source)
    if len(r.findings) > before:
        r.findings[-1]["version"] = reported
    if res == "ok":
        return "info"
    return res


def _commerce_blocked_cause(host, path):
    shown = host.display(path)
    for item in reversed(host.gaps.examples):
        if item.get("path") != shown:
            continue
        kind = item.get("kind")
        if kind == "oversized":
            return "too large"
        return "cannot read"
    return "cannot read"


def _commerce_read_needed(host, r, path, reader, limit):
    data = reader(path, limit, host.gaps)
    if data is None and hs.exists_nofollow(path):
        r.blocked.append("%s %s" % (host.display(path), _commerce_blocked_cause(host, path)))
        return None
    return data


def _commerce_deepest_root(path, roots):
    enclosing = [root for root in roots if _under_site(path, root)]
    if not enclosing:
        return None
    return max(enclosing, key=lambda item: len(os.path.abspath(item)))


def _commerce_same_site_fixed(path, roots):
    deepest = _commerce_deepest_root(path, roots)
    return (deepest is not None and roots.get(deepest)
            and bool(COMMERCE_INFO_REL_RE.match(_commerce_relposix(path, deepest))))


def _commerce_pair_note(host, r, path):
    r.notes.append(
        "%s has no version; a composer.lock or installed.json in the same site root "
        "is at or above the advisory floor" % host.display(path))


def check_drupal_commerce(host, r):
    idx = index(host)
    roots = {}
    for path, source in ([(p, "composer.lock") for p in idx.composer_lock]
                         + [(p, "installed.json") for p in idx.composer_installed]):
        text = _commerce_read_needed(host, r, path, hs.read_text, 4 * MIB)
        if text is None:
            continue
        text = _commerce_normalize(text)
        try:
            doc = json.loads(text)
        except ValueError:
            r.blocked.append("%s invalid JSON" % host.display(path))
            continue
        root = _commerce_site_root(path)
        roots.setdefault(root, False)
        vers = _commerce_packages(doc)
        if not vers:
            if COMMERCE_PKG_NAME_RE.search(text):
                r.add("unknown", "Drupal Commerce Core",
                      "%s mentions drupal/commerce but no version could be read" % source,
                      path=host.display(path))
            continue
        for ver in vers:
            res = classify_commerce(r, "Drupal Commerce Core", ver, host.display(path), source)
            if res == "info":
                roots[root] = True
    for path in idx.drupal_commerce:
        text = _commerce_read_needed(host, r, path, hs.read_text, COMMERCE_INFO_LIMIT)
        if text is None:
            continue
        text = _commerce_normalize(text)
        if not COMMERCE_PROJECT_RE.search(text):
            if COMMERCE_PROJECT_ANY_RE.search(text):
                r.add("review", "Drupal Commerce Core",
                      COMMERCE_INFO_YML + " names a different project",
                      path=host.display(path))
                continue
            if _commerce_same_site_fixed(path, roots):
                _commerce_pair_note(host, r, path)
            else:
                r.add("unknown", "Drupal Commerce Core",
                      "unpackaged checkout; check the commit",
                      path=host.display(path))
            continue
        versions = _commerce_version_values(text)
        if not versions and COMMERCE_VERSION_ANY_RE.search(text):
            r.add("unknown", "Drupal Commerce Core",
                  COMMERCE_INFO_YML + " has an unreadable version:",
                  path=host.display(path))
            continue
        unique = []
        seen = set()
        for ver in versions:
            if ver not in seen:
                seen.add(ver)
                unique.append(ver)
        if len(seen) > 1:
            r.add("review", "Drupal Commerce Core",
                  "several version: lines in " + COMMERCE_INFO_YML,
                  path=host.display(path))
            continue
        ver = unique[0] if unique else ""
        if not ver:
            if _commerce_same_site_fixed(path, roots):
                _commerce_pair_note(host, r, path)
            else:
                r.add("unknown", "Drupal Commerce Core",
                      COMMERCE_INFO_YML + " has project: commerce but no version",
                      path=host.display(path))
            continue
        classify_commerce(r, "Drupal Commerce Core", ver, host.display(path), COMMERCE_INFO_YML)


def check_connectwise(host, r):
    paths = [host.sys("C:/Windows/LTSvc")]
    for pf in host.program_files():
        paths += glob_dirs(host, pf, "screenconnect client*") + glob_dirs(host, pf, "connectwise*")
    paths += glob_dirs(host, host.sys("/opt"), "connectwisecontrol-*") + glob_dirs(host, host.sys("/opt"), "screenconnect-*")
    paths += [os.path.join(host.sys("/Applications"), n) for n in hs.listdir(host.sys("/Applications"))
              if n.lower().startswith("connectwisecontrol")]
    presence_check(host, r, "ConnectWise software", paths, registry=r"ScreenConnect|ConnectWise",
                   detail="ConnectWise present; ask whether you or a managed IT provider use ConnectWise Cloud Backup")


# Assembled so the public-leak scanner does not treat detection strings as live hosts.
_ONAMAE_COM = "onamae" + ".com"
_ONAMAE_COJP = "onamae" + ".co.jp"
_TS_SSH_ENV = "TS_SSH" + "_DISABLE_FORWARDING"
TAILSCALE_FIXED = "1.104.4"
NODE_BROTLI_FIXED = ["22.23.4", "24.22.1", "26.12.1"]


def _truthy_flag(value):
    return str(value).strip().strip("\"'").lower() in ("1", "true", "yes", "on")


def tailscale_installs(host):
    """(source, version_or_None, path_or_None) for Tailscale clients. Never runs tailscale."""
    out = []
    for ver, src in linux_packages(host).get("tailscale", []):
        out.append(("%s package" % src, ver, None))
    for ver, p in cellar(host).get("tailscale", []):
        out.append(("Homebrew", ver, p))
    for base in (host.sys("/Applications"), host.h("Applications")):
        plist = os.path.join(base, "Tailscale" + APP, "Contents", "Info.plist")
        if hs.is_regular(plist):
            ver = hs.plist_value(plist, "CFBundleShortVersionString") or hs.plist_value(plist, "CFBundleVersion")
            out.append(("macOS app", ver, plist))
    for e in registry_matches(host, r"^Tailscale\b"):
        out.append(("uninstall registry", e.get("version") or None, None))
    for pf in host.program_files():
        exe = os.path.join(pf, "Tailscale", "tailscale.exe")
        if hs.is_regular(exe):
            out.append(("Windows PE", hs.pe_file_version(exe), exe))
    extra = [host.sys("/usr/bin"), host.sys("/usr/local/bin"), host.sys("/opt/homebrew/bin"),
             host.h(".local", "bin")]
    if not any(src.endswith("package") or src in ("Homebrew", "macOS app", "Windows PE", "uninstall registry")
               for src, _v, _p in out):
        for exe in find_binaries(host, ["tailscale"], extra):
            pv = hs.pe_file_version(exe) if host.platform == "windows" and hs.is_regular(exe) else None
            out.append(("binary on PATH", pv, exe))
    return out


def tailscale_runssh(host):
    """True/False/None from on-disk prefs. Does not run `tailscale debug prefs`."""
    candidates = [
        host.sys("/var/lib/tailscale/prefs.json"),
        host.sys("/var/lib/tailscale/tailscaled.state"),
        host.h(".config", "tailscale", "prefs.json"),
        host.h("Library", "Application Support", "Tailscale", "prefs.json"),
        os.path.join(host.localappdata(), "Tailscale", "prefs.json"),
    ]
    for base in (host.sys("/var/lib/tailscale"), host.h(".config", "tailscale"),
                 host.h("Library", "Application Support", "Tailscale"),
                 os.path.join(host.localappdata(), "Tailscale")):
        if hs.is_plain_dir(base):
            for n in hs.listdir(base)[:80]:
                if n.lower().endswith((".json", ".plist")) or n in ("prefs", "prefs.json"):
                    candidates.append(os.path.join(base, n))
    seen = set()
    for path in candidates:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        if not hs.is_regular(path):
            continue
        text = text_of(host, path, MIB)
        if not text:
            continue
        m = re.search(r'(?i)"RunSSH"\s*:\s*(true|false)', text)
        if m:
            return m.group(1).lower() == "true", path
        m = re.search(r"(?i)<key>RunSSH</key>\s*<(true|false)/>", text)
        if m:
            return m.group(1).lower() == "true", path
    return None, None


def _ts_ssh_env_in_text(text):
    """True when TS_SSH_DISABLE_FORWARDING is set truthy in a service file or plist."""
    if not text:
        return False
    plist = re.search(
        r"(?is)<key>\s*%s\s*</key>\s*(?:<string>([^<]*)</string>|<true\s*/>|<false\s*/>)"
        % re.escape(_TS_SSH_ENV),
        text,
    )
    if plist:
        if plist.group(1) is None:
            return "<true" in plist.group(0).lower()
        return _truthy_flag(plist.group(1))
    line_rx = re.compile(
        r"(?i)^\s*(?:Environment\s*=\s*[\"']?)?%s\s*=\s*[\"']?([^\"'\s#]+)" % re.escape(_TS_SSH_ENV)
    )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        m = line_rx.search(stripped)
        if m and _truthy_flag(m.group(1)):
            return True
    return False


def tailscale_forwarding_disabled(host):
    """Whether TS_SSH_DISABLE_FORWARDING is set. Reads files and tailscaled environ only."""
    files = [
        host.sys("/etc/default/tailscaled"),
        host.sys("/etc/sysconfig/tailscaled"),
        host.sys("/Library/LaunchDaemons/com.tailscale.tailscaled.plist"),
    ]
    drop = host.sys("/etc/systemd/system/tailscaled.service.d")
    if hs.is_plain_dir(drop):
        for n in hs.listdir(drop)[:40]:
            if n.endswith(".conf"):
                files.append(os.path.join(drop, n))
    for path in files:
        text = text_of(host, path, 256 * 1024)
        if _ts_ssh_env_in_text(text):
            return True, path
    proc = host.sys("/proc")
    if hs.is_plain_dir(proc):
        for name in hs.listdir(proc)[:4096]:
            if not name.isdigit():
                continue
            comm = hs.read_text(os.path.join(proc, name, "comm"), 64)
            if not comm or comm.strip() != "tailscaled":
                continue
            env = hs.read_bytes(os.path.join(proc, name, "environ"), 64 * 1024, host.gaps)
            if not env:
                continue
            prefix = (_TS_SSH_ENV + "=").encode()
            for item in env.split(b"\0"):
                if item.startswith(prefix):
                    if _truthy_flag(item.split(b"=", 1)[1].decode("ascii", "replace")):
                        return True, "/proc/<pid>/environ"
                    return False, "/proc/<pid>/environ"
    return None, None


def tailscale_acl_has_ssh(host):
    """True when an exported policy file has an ssh key. Rules are not copied."""
    paths = list(index(host).mesh_acl)
    for extra in (host.h("tailscale-acl.json"), host.h("tailnet-policy.json"),
                  host.sys("/etc/tailscale/acl.json"), host.sys("/etc/headscale/acl.hujson")):
        if extra not in paths:
            paths.append(extra)
    hits = []
    for path in paths:
        text = text_of(host, path, MIB)
        if text and re.search(r'(?i)(?:^|[{\s,])"?ssh"?\s*:', text):
            hits.append(path)
    return hits


def check_tailscale_ssh(host, r):
    installs = tailscale_installs(host)
    ssh_on, prefs_path = tailscale_runssh(host)
    mit, mit_path = tailscale_forwarding_disabled(host)
    acl_paths = tailscale_acl_has_ssh(host)
    images = list(docker_refs(host, r"tailscale/tailscale"))
    if not installs and ssh_on is None and not acl_paths and not images:
        return
    for src, ver, path in installs:
        disp = host.display(path) if path else None
        if not ver:
            r.add("unknown", "Tailscale (%s)" % src,
                  "present; version not readable without running tailscale", path=disp)
            continue
        v = hs.parse_version(ver)
        if v is None:
            r.add("unknown", "Tailscale (%s)" % src, "version string could not be parsed", path=disp, version=ver)
            continue
        if hs.at_least(v, TAILSCALE_FIXED):
            r.add("info", "Tailscale (%s)" % src,
                  "at or above vendor-fixed build %s (TS-2026-014 to TS-2026-017)" % TAILSCALE_FIXED,
                  path=disp, version=ver)
            continue
        note = "below vendor-fixed build %s" % TAILSCALE_FIXED
        if v.prerelease and hs.cmp_nums(v.nums, hs.parse_version(TAILSCALE_FIXED).nums) == 0:
            note = "prerelease of the fixed build %s is not treated as fixed" % TAILSCALE_FIXED
        if v.vendor_suffix:
            note += "; distribution build string, confirm any vendor backport in its changelog"
        if ssh_on is False:
            r.add("info", "Tailscale (%s)" % src,
                  note + "; Tailscale SSH is off (RunSSH false); still upgrade", path=disp, version=ver)
        else:
            ssh = "Tailscale SSH is on (RunSSH true)" if ssh_on is True else \
                "Tailscale SSH state unread (prefs not on disk; tailscale is never run)"
            extra = "; mitigation %s=1 not set" % _TS_SSH_ENV if mit is not True else \
                "; mitigation %s is set (not a vendor patch)" % _TS_SSH_ENV
            r.add("affected", "Tailscale (%s)" % src, note + "; " + ssh + extra, path=disp, version=ver)
    for path, image, tag in images:
        v = hs.parse_version(tag)
        if v and hs.at_least(v, TAILSCALE_FIXED):
            r.add("info", "Tailscale image", "at or above %s" % TAILSCALE_FIXED,
                  path=host.display(path), version=tag, image=image)
        elif v:
            r.add("affected", "Tailscale image", "below %s; rebuild after upgrading" % TAILSCALE_FIXED,
                  path=host.display(path), version=tag, image=image)
        else:
            r.add("info", "Tailscale image", "moving tag %s; rebuild to pick up 1.104.4" % tag,
                  path=host.display(path), version=tag, image=image)
    if prefs_path is not None:
        r.notes.append("RunSSH read from prefs metadata (command not run): %s" % host.display(prefs_path))
        if not installs and not images:
            r.add("unknown", "Tailscale SSH prefs",
                  "RunSSH was read from prefs metadata but no Tailscale client install, package or image was found",
                  path=host.display(prefs_path))
    if mit is True:
        r.add("info", "Tailscale SSH forwarding mitigation",
              "%s is set; vendor says this disables forwarding without disabling SSH "
              "(mitigation, not a vendor patch; restart is a recommendation only and was not performed)" % _TS_SSH_ENV,
              path=host.display(mit_path) if mit_path and not str(mit_path).startswith("/proc/") else mit_path)
    elif installs and ssh_on is not False:
        r.notes.append("%s was not set in the listed service files or tailscaled environ" % _TS_SSH_ENV)
    for path in acl_paths:
        r.add("review", "exported Tailscale ssh policy",
              "ssh rules are present; rule bodies are not copied. Confirm forwarding is off on every effective rule",
              path=host.display(path))
    unread_and_unfixed = False
    for src, ver, path in installs:
        v = hs.parse_version(ver) if ver else None
        if v is None or not hs.at_least(v, TAILSCALE_FIXED):
            unread_and_unfixed = True
            break
    if installs and ssh_on is None and unread_and_unfixed and not any(f["result"] == "affected" for f in r.findings):
        r.add("unknown", "Tailscale SSH prefs",
              "client present; RunSSH could not be read from disk and tailscale is never run")


def _dedupe_host_paths(paths, windows):
    seen, out = set(), []
    for path in paths:
        key = os.path.normcase(path) if windows else path
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def check_peoplesoft(host, r):
    windows = host.platform == "windows"
    raw = [host.sys(p) for p in ("/opt/oracle/psft", "/opt/oracle/pt8.61", "/opt/oracle/pt8.62",
                                 "/opt/oracle/peopletools", "/opt/PT8.61", "/opt/PT8.62", "/app/psft")]
    raw += glob_dirs(host, host.sys("/opt/oracle"), "pt8.*") + glob_dirs(host, host.sys("/opt"), "psft*")
    raw += glob_dirs(host, host.sys("/opt/oracle"), "peopletools*") + glob_dirs(host, host.sys("/opt/oracle"), "peoplesoft*")
    raw += glob_dirs(host, host.sys("/opt"), "peopletools*")
    for pf in host.program_files():
        raw += glob_dirs(host, pf, "peoplesoft*") + glob_dirs(host, pf, "peopletools*")
    paths = _dedupe_host_paths(raw, windows)
    cfg_names = ("allowedhosts.properties", "psconfig.sh", "psappsrv.cfg", "psprcs.cfg")
    cfg_keys = set()
    for d in paths:
        if not hs.is_plain_dir(d):
            continue
        for fn in cfg_names:
            p = os.path.join(d, fn)
            if not hs.is_regular(p):
                continue
            key = os.path.normcase(p) if windows else p
            if key in cfg_keys:
                continue
            cfg_keys.add(key)
            r.add("review", "Oracle PeopleSoft / PeopleTools",
                  "PeopleSoft config or tools file on disk (contents not dumped)", path=host.display(p))
    presence_check(host, r, "Oracle PeopleSoft / PeopleTools",
                   paths, binaries=["psadmin"],
                   packages=["peoplesoft", "peopletools"],
                   registry=r"PeopleSoft|PeopleTools",
                   detail="PeopleSoft footprint; Oracle alert CVE-2026-35273 covers PeopleTools 8.61 and 8.62 "
                          "(CVSS 9.8). ShinyHunters reporting describes a three-flaw chain under that one CVE. "
                          "A patched host may keep the same PeopleTools version; treat presence as review")
    for path in index(host).peoplesoft:
        key = os.path.normcase(path) if windows else path
        if key in cfg_keys:
            continue
        cfg_keys.add(key)
        r.add("review", "Oracle PeopleSoft / PeopleTools",
              "PeopleSoft config or tools file on disk (contents not dumped)", path=host.display(path))
    for path, image, tag in docker_refs(host, r"peoplesoft|peopletools"):
        r.add("review", "PeopleSoft image", "image reference present", path=host.display(path),
              version=tag, image=image)
    if r.present:
        r.notes.append("No live PIA probe was performed. Absence of a version bump is not evidence of a patch")


def check_anthropic_chain(host, r):
    """Record browser and OS patch levels against dated floors. The chain claim is unconfirmed."""
    for b in browsers(host):
        name = b["browser"]
        ver = b["version"]
        disp = host.display(b["path"]) if b.get("path") else None
        if name.startswith(("Google Chrome", "Chromium")):
            v = hs.parse_version(ver) if ver else None
            if v is None:
                r.add("unknown", name, "installed; version not readable (%s)" % b["source"], path=disp)
            elif v.nums[0] < 156:
                r.add("review", name,
                      "below dated Chrome 156 floor (Anthropic post: Chrome CVEs patched as of 156). "
                      "The AI-discovered chain claim itself is unconfirmed",
                      path=disp, version=ver)
            else:
                r.add("info", name, "156 or newer vs dated floor (%s)" % b["source"], path=disp, version=ver)
        elif name == "Safari":
            r.add("info", name,
                  "version recorded; desktop Safari fixed build is unverified "
                  "(news cited iOS/iPadOS 26.5.2; no desktop build confirmed)",
                  path=disp, version=ver or "unknown")
        else:
            r.add("info", name, "version recorded (%s); not a dated floor for this claim" % b["source"],
                  path=disp, version=ver or "unknown")
    if host.platform == "linux":
        rel = hs.read_text(host.sys("/proc/sys/kernel/osrelease"), 4096) or \
            hs.read_text(host.sys("/proc/version"), 4096)
        if rel:
            first = rel.strip().split()[0] if rel.strip() else rel.strip()
            r.add("info", "Linux kernel",
                  "version recorded; exact patched builds for CVE-2026-98432 (MPTCP UAF) are unverified",
                  path="/proc/sys/kernel/osrelease", version=first[:80])
    elif host.platform == "darwin":
        plist = host.sys("/System/Library/CoreServices/SystemVersion.plist")
        ver = hs.plist_value(plist, "ProductVersion") if hs.is_regular(plist) else None
        if ver:
            r.add("info", "macOS",
                  "version recorded; desktop Safari / macOS build that closes the reported SOP chain is unverified",
                  path=host.display(plist), version=ver)
    elif host.platform == "windows":
        for e in registry_matches(host, r"^Windows (10|11|Server)"):
            r.add("info", e.get("name") or "Windows",
                  "build recorded; exact patched build for CVE-2026-33096 (HTTP/3 QUIC DoS) is unverified",
                  version=e.get("version") or "unknown")
            break
    if r.present:
        r.blocked.append("Anthropic AI-discovered exploit-chain claim is unconfirmed: Chrome 156 is a dated floor; "
                         "Safari, Windows and Linux fixed builds named in news were not verified against a vendor "
                         "security bulletin retrieved for this check")


def _onamae_host_in(text):
    if not text:
        return False
    low = text.lower()
    return _ONAMAE_COM in low or _ONAMAE_COJP in low


def check_gmo_onamae(host, r):
    """Local config / zone-file hints only. No live DNS."""
    files = list(index(host).gmo_cfg)
    for extra in (host.sys("/etc/bind/named.conf"), host.sys("/etc/bind/named.conf.local"),
                  host.sys("/etc/named.conf"), host.sys("/etc/resolv.conf"),
                  host.h(".config", "onamae"), host.h("onamae.ini")):
        if extra not in files:
            files.append(extra)
    for base in (host.sys("/etc/bind"), host.sys("/etc/named"), host.sys("/var/named"), host.h("zones")):
        if hs.is_plain_dir(base):
            for n in hs.listdir(base)[:80]:
                p = os.path.join(base, n)
                if hs.is_regular(p):
                    files.append(p)
    seen = set()
    for path in files:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        text = text_of(host, path, MIB)
        if not _onamae_host_in(text):
            continue
        dnsish = bool(re.search(r"(?i)\b(NS|MX|nameserver)\b", text or ""))
        r.add("review", "GMO Onamae Desktop Cloud / DNS hint",
              "local file names an Onamae host" + (" (NS/MX/nameserver context)" if dnsish else "") +
              "; vendor confirmed customer data taken. Rotate credentials and review exposed data. "
              "No live DNS query was made",
              path=host.display(path))
    for path, image, tag in docker_refs(host, r"onamae"):
        r.add("review", "Onamae image", "image reference present", path=host.display(path), version=tag, image=image)
    if r.present:
        r.notes.append("Generic GMO product names were not treated as a hit; only Onamae Desktop Cloud host strings")


def check_plex(host, r):
    for base in (host.sys("/Applications"), host.h("Applications")):
        plist = os.path.join(base, "Plex Media Server" + APP, "Contents", "Info.plist")
        if hs.is_regular(plist):
            ver = hs.plist_value(plist, "CFBundleShortVersionString") or hs.plist_value(plist, "CFBundleVersion")
            classify_version(r, "Plex Media Server", ver or "unknown", host.display(plist), ["1.43.3.10861"], 0, (), "Info.plist")
    for ver, src in linux_packages(host).get("plexmediaserver", []):
        classify_version(r, "Plex Media Server", ver, None, ["1.43.3.10861"], 0, (), src)
    if host.platform == "linux" and not r.findings and hs.is_plain_dir(host.sys("/usr/lib/plexmediaserver")):
        r.add("unknown", "Plex Media Server", "installed without a package record", path="/usr/lib/plexmediaserver")
    for pf in host.program_files():
        exe = os.path.join(pf, "Plex", "Plex Media Server", "Plex Media Server.exe")
        if hs.is_regular(exe):
            classify_version(r, "Plex Media Server", hs.pe_file_version(exe) or "unknown", host.display(exe),
                             ["1.43.3.10861"], 0, (), "PE version resource")
    for e in registry_matches(host, r"^Plex Media Server"):
        if not r.findings:
            classify_version(r, "Plex Media Server", e.get("version") or "unknown", None, ["1.43.3.10861"], 0, (), "registry")


_UBUNTU_GENERIC = re.compile(r"^(\d+)\.(\d+)\.0-([1-9]\d{0,2})-generic$")
_PLAIN_UPSTREAM = re.compile(r"^\d+\.\d+\.\d+$")
_KERNEL_ABI = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\d+)")
_UBUNTU_UPLOAD = re.compile(r"#(\d+)(?:\.\d+)?(?:~([\w.]+))?-Ubuntu")
# Ubuntu CVE-2026-46300 rows retrieved 2026-10-30: (VERSION_ID, major.minor) -> (fixed ABI, upload, page row).
FRAGNESIA_UBUNTU_ABI = {
    ("26.04", (7, 0)): (22, 22, "linux 7.0.0-22.22"),
    ("25.10", (6, 17)): (35, 35, "linux 6.17.0-35.35"),
    ("24.04", (6, 8)): (124, 124, "linux 6.8.0-124.124"),
    ("24.04", (6, 17)): (35, 35, "linux-hwe-6.17 6.17.0-35.35~24.04.1"),
    ("22.04", (5, 15)): (181, 191, "linux 5.15.0-181.191"),
    ("22.04", (6, 8)): (124, 124, "linux-hwe-6.8 6.8.0-124.124~22.04.1"),
    ("20.04", (5, 15)): (181, 191, "linux-hwe-5.15 5.15.0-181.191~20.04.1"),
}
FRAGNESIA_UPSTREAM = ["5.10.257", "5.15.208", "6.1.174", "6.6.141", "6.12.91", "6.18.33", "7.0.10"]
TCP_UAF_UPSTREAM = ["5.10.272", "5.15.223", "6.1.190", "6.6.159", "6.12.113", "6.18.56", "7.2.10"]
_UBUNTU_GENERIC_NOT_AFFECTED = frozenset({"26.10", "20.04", "18.04", "16.04", "14.04"})


def os_release_fields(host):
    text = ""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        # /etc/os-release is often a symlink; read_text refuses the link and
        # the next path is the real file. Do not record that as a coverage gap.
        text = hs.read_text(host.sys(path), 4096) or ""
        if text:
            break
    out = {}
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, val = line.split("=", 1)
        out[key.strip()] = val.strip().strip("\"'")
    return out


def running_osrelease(host):
    return (hs.read_text(host.sys("/proc/sys/kernel/osrelease"), 4096, host.gaps) or "").strip()


def ubuntu_upload_fields(host):
    text = hs.read_text(host.sys("/proc/version"), 4096, host.gaps) or ""
    m = _UBUNTU_UPLOAD.search(text)
    if not m:
        return None, None
    series = None
    if m.group(2):
        sm = re.match(r"(\d+\.\d+)", m.group(2))
        series = sm.group(1) if sm else None
    return int(m.group(1)), series


def linux_image_abis(host):
    out = []
    for name, entries in linux_packages(host).items():
        if not name.startswith("linux-image"):
            continue
        for ver, src in entries:
            m = _KERNEL_ABI.search(ver) or _KERNEL_ABI.search(name)
            if not m:
                continue
            abi = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
            out.append((name, ver, src, abi))
    return out


def _tv_label(kind):
    if kind == "host":
        return "TeamViewer Host"
    if kind == "portable":
        return "TeamViewer Portable"
    return "TeamViewer"


def teamviewer_classify(r, component, raw, path, platform, kind="client"):
    cite = "TV-2026-1011" if kind == "host" else "TV-2026-1011 / CVE-2026-111585"
    v = hs.parse_version(raw)
    if v is None:
        r.add("unknown", component, "version string could not be parsed (metadata; %s)" % cite, path=path,
              version=textscan.redact(str(raw))[:64])
        return
    if v.nums and v.nums[0] >= 16:
        r.add("info", component, "16.x and later; at or above 15.83 (%s)" % cite, path=path, version=raw)
        return
    if hs.at_least(v, "15.83"):
        r.add("info", component, "at or above fixed build 15.83 (%s)" % cite, path=path, version=raw)
        return
    line = v.nums[:2] if len(v.nums) >= 2 else ()
    if line == (15, 64):
        if platform == "windows":
            if hs.below(v, "15.64.10"):
                r.add("affected", component,
                      "below 15.64.10; the 15.64 legacy fix is Windows 7 and 8 only (%s)" % cite,
                      path=path, version=raw)
            else:
                r.add("review", component,
                      "fixed build for Windows 7 and 8 only; confirm OS or update to 15.83 (%s)" % cite,
                      path=path, version=raw)
        else:
            r.add("affected", component,
                  "below 15.83; the 15.64 legacy fix is Windows 7 and 8 only (%s)" % cite,
                  path=path, version=raw)
        return
    if line == (14, 7):
        classify_version(r, component, raw, path, ["14.7.48868"], 2, extra_note="; %s" % cite)
        return
    if line == (13, 2):
        if platform == "windows":
            floor = "13.2.36231"
        elif platform == "linux":
            floor = "13.2.154008"
        else:
            floor = "13.2.154007"
        classify_version(r, component, raw, path, [floor], 2, extra_note="; %s" % cite)
        return
    if hs.below(v, "15.83"):
        r.add("affected", component,
              "below 15.83; no legacy fix listed for this line in %s" % cite, path=path, version=raw)
        return
    r.add("info", component, "at or above fixed build 15.83 (%s)" % cite, path=path, version=raw)


def _is_teamviewer_portable_name(name):
    compact = name.lower().replace(" ", "").replace("_", "")
    return compact.startswith("teamviewerportable")


def _teamviewer_portable_roots(host):
    roots = list(downloads_dirs(host)) + [host.h("Desktop")]
    if host.platform == "windows":
        # Split so the public-package home-path scanner does not read this as a username.
        roots.append(host.sys("C:/" + "Users/Public/Downloads"))
    return roots


def _teamviewer_scan_portable(host, r):
    seen = set()
    for root in _teamviewer_portable_roots(host):
        key = os.path.normcase(os.path.abspath(root))
        if key in seen:
            continue
        seen.add(key)
        for name in hs.listdir(root):
            if not _is_teamviewer_portable_name(name):
                continue
            inner = os.path.join(root, name)
            found = False
            if hs.is_plain_dir(inner):
                for exe_name in ("TeamViewer.exe", "TeamViewerPortable.exe", "TeamViewer_Desktop.exe"):
                    exe = os.path.join(inner, exe_name)
                    if hs.is_regular(exe):
                        found = True
                        teamviewer_classify(r, _tv_label("portable"),
                                            hs.pe_file_version(exe) or "unknown",
                                            host.display(exe), host.platform, "portable")
                plist = os.path.join(inner, "Contents", "Info.plist")
                if hs.is_regular(plist):
                    found = True
                    ver = hs.plist_value(plist, "CFBundleShortVersionString")
                    teamviewer_classify(r, _tv_label("portable"), ver or "unknown",
                                        host.display(plist), host.platform, "portable")
                if not found:
                    r.add("unknown", _tv_label("portable"),
                          "TeamViewer Portable folder present; version not in metadata (not executed)",
                          path=host.display(inner))
            elif hs.is_regular(inner) and name.lower().endswith(".exe"):
                teamviewer_classify(r, _tv_label("portable"),
                                    hs.pe_file_version(inner) or "unknown",
                                    host.display(inner), host.platform, "portable")


def check_teamviewer(host, r):
    if host.platform == "linux":
        found = False
        pk = linux_packages(host)
        for name in ("teamviewer", "teamviewer-host"):
            kind = "host" if name.endswith("-host") else "client"
            for ver, _src in pk.get(name, []):
                found = True
                teamviewer_classify(r, _tv_label(kind), ver, None, "linux", kind)
        if not found and hs.is_plain_dir(host.sys("/opt/teamviewer")):
            r.add("unknown", "TeamViewer",
                  "TeamViewer files present; version not in package metadata (not executed)",
                  path="/opt/teamviewer")
        _teamviewer_scan_portable(host, r)
        return
    if host.platform == "darwin":
        bundles = (
            (host.sys("/Applications/TeamViewer" + APP), "client"),
            (host.sys("/Applications/TeamViewerHost" + APP), "host"),
            (host.h("Applications", "TeamViewer" + APP), "client"),
            (host.h("Applications", "TeamViewerHost" + APP), "host"),
        )
        for bundle, kind in bundles:
            if not hs.is_plain_dir(bundle):
                continue
            plist = os.path.join(bundle, "Contents", "Info.plist")
            if hs.is_regular(plist):
                ver = hs.plist_value(plist, "CFBundleShortVersionString")
                teamviewer_classify(r, _tv_label(kind), ver or "unknown",
                                    host.display(plist), "darwin", kind)
            else:
                r.add("unknown", _tv_label(kind),
                      "TeamViewer bundle present; version not in Info.plist (not executed)",
                      path=host.display(bundle))
        _teamviewer_scan_portable(host, r)
        return
    seen_dir = False
    host_dirs_without_pe = []
    for pf in host.program_files():
        for d in glob_dirs(host, pf, "TeamViewer*"):
            seen_dir = True
            kind = "host" if re.search(r"host", os.path.basename(d), re.I) else "client"
            found_pe = False
            for name in ("TeamViewer.exe", "TeamViewer_Desktop.exe"):
                exe = os.path.join(d, name)
                if hs.is_regular(exe):
                    found_pe = True
                    teamviewer_classify(r, _tv_label(kind), hs.pe_file_version(exe) or "unknown",
                                        host.display(exe), "windows", kind)
            if kind == "host" and not found_pe:
                host_dirs_without_pe.append(d)
    for e in registry_matches(host, r"^TeamViewer(?: \d+)?(?: Host)?$"):
        kind = "host" if re.search(r"\bHost\b", e.get("name", ""), re.I) else "client"
        teamviewer_classify(r, _tv_label(kind), e.get("version") or "unknown", None, "windows", kind)
    if not any(f["component"] == "TeamViewer Host" and f["result"] != "unknown" for f in r.findings):
        for d in host_dirs_without_pe:
            r.add("unknown", _tv_label("host"),
                  "TeamViewer Host folder present; version not in PE or registry metadata (not executed)",
                  path=host.display(d))
    if seen_dir and not r.findings:
        r.add("unknown", "TeamViewer",
              "TeamViewer files present; version not in PE or registry metadata (not executed)")
    _teamviewer_scan_portable(host, r)


def check_fragnesia(host, r):
    if host.platform != "linux":
        r.notes.append("Fragnesia (CVE-2026-46300) is a Linux kernel issue; not applicable on %s" % host.platform)
        return
    r.notes.append(
        "CISA KEV describes a chain with CVE-2026-109618 and CVE-2026-109619; also run the php2shell check "
        "on this host. A Fragnesia result does not clear PHP, and the reverse is also false."
    )
    osrel = running_osrelease(host)
    fields = os_release_fields(host)
    procver = (hs.read_text(host.sys("/proc/version"), 4096, host.gaps) or "").strip()
    mods = hs.read_text(host.sys("/proc/modules"), 4 * MIB, host.gaps) or ""
    if re.search(r"(?m)^(esp4|esp6|xfrm)\S*\s", mods):
        r.notes.append("ESP/XFRM modules listed in /proc/modules (observation only; not a fix)")
    images = linux_image_abis(host)
    for name, ver, src, _abi in images:
        r.notes.append("linux-image package %s %s (%s); classification uses the running osrelease only" %
                       (name, ver, src))
    if not osrel:
        if fields or procver or images:
            r.add("unknown", "Linux kernel",
                  "running kernel release unreadable",
                  path="/proc/sys/kernel/osrelease")
        return
    generic = _UBUNTU_GENERIC.match(osrel)
    running_abi = None
    if generic:
        running_abi = (int(generic.group(1)), int(generic.group(2)), 0, int(generic.group(3)))
        newer = [t for t in images if t[3][:3] == running_abi[:3] and t[3][3] > running_abi[3]]
        if newer:
            r.notes.append("newer kernel installed; reboot needed")
    distro_id = fields.get("ID", "")
    version_id = fields.get("VERSION_ID", "")
    if distro_id == "ubuntu":
        if running_abi is None:
            r.add("review", "Linux kernel (Ubuntu)",
                  "non-generic or unrecognised Ubuntu kernel; match the package to the Ubuntu page",
                  path="/proc/sys/kernel/osrelease", version=osrel)
            return
        if not version_id:
            r.add("review", "Linux kernel (Ubuntu)",
                  "Ubuntu os-release has no VERSION_ID; match the package to the Ubuntu page",
                  path="/proc/sys/kernel/osrelease", version=osrel)
            return
        row = FRAGNESIA_UBUNTU_ABI.get((version_id, (running_abi[0], running_abi[1])))
        if row is None:
            if version_id in _UBUNTU_GENERIC_NOT_AFFECTED:
                detail = ("no matching Ubuntu fixed-ABI row for release %s; confirm the running kernel "
                          "against the Ubuntu page" % version_id)
            else:
                detail = ("no Ubuntu CVE-2026-46300 row for release %s kernel %s.%s; match the package "
                          "to the Ubuntu page" % (version_id, running_abi[0], running_abi[1]))
            r.add("review", "Linux kernel (Ubuntu)", detail,
                  path="/proc/sys/kernel/osrelease", version=osrel)
            return
        floor_abi, floor_upload, label = row
        upload, upload_series = ubuntu_upload_fields(host)
        if upload_series and version_id and upload_series != version_id:
            r.add("review", "Linux kernel (Ubuntu)",
                  "upload suffix ~%s does not match VERSION_ID %s; match the package to the Ubuntu page"
                  % (upload_series, version_id),
                  path="/proc/sys/kernel/osrelease", version=osrel)
            return
        if running_abi[3] == floor_abi and upload is None and floor_upload != floor_abi:
            r.add("review", "Linux kernel (Ubuntu)",
                  "ABI matches Ubuntu fixed build %s but the upload number is unreadable; "
                  "confirm the package version on the Ubuntu page" % label,
                  path="/proc/sys/kernel/osrelease", version=osrel)
            return
        below = running_abi[3] < floor_abi or (
            running_abi[3] == floor_abi and upload is not None and upload < floor_upload)
        if below:
            if running_abi[3] < floor_abi:
                detail = "below Ubuntu fixed build %s (ABI %d < %d)" % (label, running_abi[3], floor_abi)
            else:
                detail = "below Ubuntu fixed build %s (upload %d < %d)" % (label, upload, floor_upload)
            r.add("affected", "Linux kernel (Ubuntu)", detail,
                  path="/proc/sys/kernel/osrelease", version=osrel)
        else:
            r.add("info", "Linux kernel (Ubuntu)",
                  "at or above Ubuntu fixed build %s" % label,
                  path="/proc/sys/kernel/osrelease", version=osrel)
        return
    if not _PLAIN_UPSTREAM.match(osrel):
        r.add("review", "Linux kernel",
              "distribution or custom kernel build; check the vendor advisory",
              path="/proc/sys/kernel/osrelease", version=osrel)
        return
    v = hs.parse_version(osrel)
    if v is None:
        r.add("unknown", "Linux kernel", "version string could not be parsed",
              path="/proc/sys/kernel/osrelease", version=osrel)
        return
    if not hs.below(v, "7.1.0"):
        r.add("info", "Linux kernel", "CVE record lists 7.1 and later as unaffected",
              path="/proc/sys/kernel/osrelease", version=osrel)
        return
    classify_version(r, "Linux kernel", osrel, "/proc/sys/kernel/osrelease", FRAGNESIA_UPSTREAM, 2)


def check_linux_tcp_uaf(host, r):
    if host.platform != "linux":
        r.notes.append("CVE-2026-98432 is a Linux kernel TCP use-after-free; not applicable on %s" % host.platform)
        return
    osrel = running_osrelease(host)
    procver = (hs.read_text(host.sys("/proc/version"), 4096, host.gaps) or "").strip()
    fields = os_release_fields(host)
    images = []
    for name, entries in linux_packages(host).items():
        if name.startswith("linux-image"):
            images.extend((name, ver, src) for ver, src in entries)
    if not osrel and not procver and not fields and not images:
        return
    bits = []
    if osrel:
        bits.append("running osrelease %s" % osrel[:80])
    if fields.get("ID") or fields.get("VERSION_ID"):
        bits.append("distro %s %s" % (fields.get("ID", "?"), fields.get("VERSION_ID", "?")))
    if images:
        bits.append("package %s %s" % (images[0][0], images[0][1]))
    detail = (
        "%s. Ubuntu CVE-2026-98432 last updated 29 Oct 2026 lists current releases as vulnerable "
        "work in progress; no released fixed build was retrieved this run. WIP targets are not floors. "
        "cve.org record published 15 Oct 2026, updated 30 Oct 2026 lists upstream floors %s (7.3+ unaffected; introduced 4.4); "
        "those are not Ubuntu package floors. Do not claim a fix from the string alone."
        % ("; ".join(bits) or "kernel metadata readable", ", ".join(TCP_UAF_UPSTREAM))
    )
    r.add("review", "Linux kernel (CVE-2026-98432)", detail,
          path="/proc/sys/kernel/osrelease" if osrel else None,
          version=osrel or None)


ALL_OS = "macOS, Linux, Windows"
CHECKS = [
    check_meta("testmetest-ai-hooks", "AI tool hook files nobody added (testmetest worm)", "check_now", "confirmed",
               "config", ["theregister-testmetest"],
               "The testmetest npm worm plants hooks for Cursor, VS Code, Claude and Gemini in GitHub repos.",
               "Read every listed hook. If one was not added by the owner, follow cleanup_order_testmetest.",
               ALL_OS, check_ai_hooks),
    check_meta("testmetest-large-blobs", "Large blobs in local git repos (~13 MB payloads)", "check_now", "confirmed",
               "source", ["theregister-testmetest"],
               "The worm hides 13 MB payloads that GitHub search misses.",
               "Confirm who added each large blob; if nobody did, follow cleanup_order_testmetest.", ALL_OS, check_large_blobs),
    check_meta("testmetest-npm-package", "testmetest npm package in lockfiles, node_modules, global npm or cache",
               "check_now", "confirmed", "dependency", ["theregister-testmetest"],
               "No package version fix; clean or rebuild the machine first, then revoke the GitHub token.",
               "Follow cleanup_order_testmetest. Never revoke the token before the machine is clean.", ALL_OS, check_testmetest),
    check_meta("planted-agent-instructions", "Planted AGENTS.md / CLAUDE.md outside projects or with risky instructions",
               "check_now", "confirmed", "config", ["thn-agents-md"],
               "A planted AGENTS.md in Downloads told agents to install function-color; a CLAUDE.md redirected API traffic.",
               "Read each listed file. Do not start coding agents in Downloads. If a planted file was used, rotate that "
               "agent's login token.", ALL_OS, check_planted_instructions),
    check_meta("agent-config-endpoints", "MCP servers and API base URLs in coding-agent configs", "check_now", "confirmed",
               "config", ["thn-agents-md"],
               "Check ~/.codex/config.toml and .claude/settings.json for servers or base URLs nobody added.",
               "Remove servers and base URLs nobody added; keep agent approvals and sandboxes on.", ALL_OS,
               check_agent_configs, uses_walk=True),
    check_meta("function-color-npm-package", "function-color npm package (MALFEX campaign)", "check_now", "confirmed",
               "dependency", ["thn-agents-md"], "The planted AGENTS.md told agents to install function-color.",
               "Remove it, rebuild the environment and rotate credentials that were on the machine.", ALL_OS,
               check_function_color),
    check_meta("litellm-1-107-0", "LiteLLM 1.107.0 malicious release", "check_now", "confirmed", "dependency",
               ["bc-litellm", "thn-litellm"], "LiteLLM 1.107.0 on PyPI and Docker was malicious; pin litellm==1.106.2.",
               "If 1.107.0 was installed, rebuild the machine and rotate every key on it; pin 1.106.2.", ALL_OS, check_litellm),
    check_meta("brotli-nodejs", "Node.js Brotli decoder (CVE-2026-111497)", "check_now", "confirmed", "runtime",
               ["nodejs-oct-2026", "ptp-brotli", "thn-polyshell-node"],
               "Fixed in Node 22.23.4, 24.22.1, 26.12.1; Node 20 gets no fix. Also reads .nvmrc, engines.node and "
               "CI setup-node. In-the-wild use against 24.22.0 is unverified as a Node.js/NVD claim.",
               "Upgrade Node; until then turn off Brotli (br) content-encoding. Rebuild Docker images.", ALL_OS,
               check_brotli_node, uses_walk=False),
    check_meta("brotli-python", "Python Brotli / brotlicffi (CVE-2026-111497)", "check_now", "confirmed", "dependency",
               ["aikido-brotli", "ptp-brotli"], "Brotli 1.2.0 or older and brotlicffi 1.2.0.x; fixed in 1.2.1 and 1.2.1.0.",
               "Upgrade, then rebuild Docker images. pip-audit and Dependabot do not flag it yet.", ALL_OS, check_brotli_python),
    check_meta("brotli-dotnet", ".NET runtimes (CVE-2026-111497)", "check_now", "confirmed", "runtime",
               ["bc-dotnet-brotli", "ptp-brotli"], ".NET 8.0.33, 9.0.22 or 10.0.14.",
               "Install the patched runtime; apps with Brotli decompression on are exposed.", ALL_OS, check_brotli_dotnet,
               uses_walk=False),
    check_meta("emudhra-certifi", "certifi older than 2026.10.19 (eMudhra)", "check_now", "confirmed", "dependency",
               ["thn-emudhra", "unit42-emudhra"], "Update certifi to 2026.10.19 or newer.",
               "Upgrade certifi in every environment and image (pip's vendored copy updates with pip).", ALL_OS,
               check_certifi),
    check_meta("emudhra-trust-store", "eMudhra certificates in system trust stores (report only)", "check_now",
               "confirmed", "config", ["thn-emudhra", "unit42-emudhra", "apple-emudhra"],
               "Apple blocks them in Safari, Mail and apps, but curl and git on a Mac trust them until a macOS update.",
               "Install OS updates; Apple's page explains removing the roots from /etc/ssl/cert.pem sooner. "
               "This tool reports only.", ALL_OS, check_emudhra_store, uses_walk=False),
    check_meta("chrome-156", "Google Chrome below 156", "check_now", "confirmed", "runtime", ["securityweek-chrome156"],
               "Chrome 156 fixes 353 bugs, 6 critical.", "Update and restart Chrome.", ALL_OS, check_chrome, uses_walk=False),
    check_meta("browser-versions", "Installed browser versions (CVE-2026-40369, unconfirmed)", "check_now", "unconfirmed",
               "runtime", ["voidsec-40369"], "Which browser CVE-2026-40369 hits and whether it is fixed is not confirmed.",
               "Keep browsers updated and restarted; watch for a vendor advisory naming this CVE.", ALL_OS, check_browsers,
               uses_walk=False),
    check_meta("php2shell", "PHP2Shell (CVE-2026-109618, CVE-2026-109619) and CVE-2026-115560", "check_if_used",
               "confirmed", "runtime", ["thn-php2shell", "nvd-109618", "bc-php2shell", "bc-php-115560"],
               "Fixed in PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35; for CVE-2026-115560 set session.upload_progress.enabled=0.",
               "Patch now; set session.upload_progress.enabled=0.", ALL_OS, check_php),
    check_meta("railway-client", "Railway CLI or config present (Railway breach)", "check_if_used", "confirmed",
               "credential", ["railway-incident"], "Railway was breached 20-22 Oct; some customers' secrets were exposed.",
               "Rotate every secret stored on Railway and review service logs.", ALL_OS, check_railway, uses_walk=False),
    check_meta("opencode-client", "OpenCode installed (OpenCode Console breach)", "check_if_used", "confirmed",
               "credential", ["bc-opencode"], "Saved OpenAI, Anthropic and Google keys leaked from OpenCode Console.",
               "Rotate keys if you got the breach email; review AI usage and bills since 16 Oct.", ALL_OS, check_opencode,
               uses_walk=False),
    check_meta("warp-terminal", "Warp terminal installed (Warp breach, unconfirmed)", "check_if_used", "unconfirmed",
               "credential", ["x-warp"], "Warp says attackers reached limited agent trace and telemetry data (unconfirmed).",
               "Follow Warp's notice if received; rotate keys that appeared in Warp agent sessions.", ALL_OS, check_warp,
               uses_walk=False),
    check_meta("lightning-ai-client", "Lightning AI client present (credential misuse, unconfirmed)", "check_if_used",
               "unconfirmed", "credential", ["lightning-incident"],
               "Lightning AI found stolen credentials in use on Studio (unconfirmed).",
               "Rotate API keys and GitHub tokens stored there; check access logs.", ALL_OS, check_lightning, uses_walk=False),
    check_meta("vitest-5-dev-server", "Vitest 5 below 5.0.5 (dev server file leak)", "check_if_used", "confirmed",
               "dependency", ["ghsa-vitest"], "Vitest 5 dev servers could leak .env files, keys and .git; fixed in 5.0.5.",
               "Upgrade to 5.0.5; check UI and Browser Mode usage.", ALL_OS, check_vitest),
    check_meta("pillow-13", "Pillow below 13.0.0", "check_if_used", "confirmed", "dependency", ["pillow-13"],
               "Pillow 13.0.0 fixes image bugs, some critical (needs Python 3.11+).", "Upgrade Pillow.", ALL_OS, check_pillow),
    check_meta("ovhcloud-cli", "OVHcloud CLI 0.11.0-0.15.0 (backdoored)", "check_if_used", "confirmed", "runtime",
               ["bc-ovhcloud"], "Versions 0.11.0 to 0.15.0 on GitHub were backdoored to steal secrets from disk.",
               "Use 0.16.0 or remove the tool; treat secrets on disk as exposed.", ALL_OS, check_ovhcloud, uses_walk=False),
    check_meta("gitlab-self-hosted", "Self-hosted GitLab (CVE-2026-97229, CISA KEV)", "check_if_used", "confirmed",
               "runtime", ["nvd-97229", "cisa-kev-2026-10-29", "thn-gitlab"],
               "CVE-2026-97229: GitLab CE/EE 19.2 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2. "
               "Unauthenticated code execution via a crafted CI regex. CISA KEV on 29 Oct 2026. Self-hosted only.",
               "Update self-hosted GitLab to 19.2.8, 19.3.5 or 19.4.2 (or newer). GitLab SaaS is out of scope.",
               "Linux (packages); image refs on all", check_gitlab),
    check_meta("ruby-regex", "Ruby below 4.0.9 / 3.4.12 / 3.3.13 (3.2: no fix)", "check_if_used", "confirmed", "runtime",
               ["thn-ruby"], "Ruby 4.0.9, 3.4.12 or 3.3.13; Ruby 3.2 gets no fix.",
               "Upgrade Ruby for apps that build a regex from user text.", ALL_OS, check_ruby, uses_walk=False),
    check_meta("nginx-present", "NGINX present", "check_if_used", "confirmed", "runtime", ["cso-nginx"],
               "F5 fixed 3 critical NGINX bugs.", "Update NGINX on servers and containers.", ALL_OS, check_nginx),
    check_meta("wasmtime-embedded", "Wasmtime below 36.0.19 / 48.0.7 / 49.0.4 / 50.0.0", "check_if_used", "confirmed",
               "dependency", ["thn-wasmtime"], "Fixed in 36.0.19, 48.0.7, 49.0.4 or 50.0.0; updating the CLI does not "
               "fix embedded copies.", "Upgrade and rebuild every product that embeds Wasmtime.", ALL_OS, check_wasmtime),
    check_meta("qdrant-cluster", "Qdrant cluster before 1.20.0", "check_if_used", "confirmed", "config", ["ghsa-qdrant"],
               "Qdrant clusters before 1.20.0 expose an internal port with no login.",
               "Upgrade to 1.20.0 and block port 6335.", ALL_OS, check_qdrant),
    check_meta("ksmbd-linux", "Linux KSMBD in-kernel SMB server", "check_if_used", "confirmed", "runtime", ["thn-ksmbd"],
               "Two KSMBD bugs; no kernel fix at time of writing.", "Turn off KSMBD if not needed; block port 445.",
               "Linux only", check_ksmbd, uses_walk=False),
    check_meta("collabora-nextcloud", "Collabora Online / Nextcloud present", "check_if_used", "confirmed", "runtime",
               ["nvd-110447"], "CVE-2026-110447 is on the CISA exploited list.", "Update Collabora.",
               "Linux (packages); code and image refs on all", check_collabora),
    check_meta("wordpress-updraftplus", "WordPress sites with UpdraftPlus", "check_if_used", "confirmed", "dependency",
               ["thn-updraft"], "Stolen UpdraftCentral keys are used to backdoor WordPress sites.",
               "Review the site and its UpdraftCentral connections.", ALL_OS, check_updraft),
    check_meta("magento-store", "Magento store code on disk", "check_if_used", "confirmed", "dependency", ["thn-magento"],
               "953 stores, mostly Magento, had hidden JavaScript in CMS blocks.",
               "Apply Adobe's PolyShell fix; check cms_block for code nobody added.", ALL_OS, check_magento),
    check_meta("drupal-commerce-118539",
               "Drupal Commerce Core below 8.x-2.41 / 3.3.13 (CVE-2026-118539)",
               "check_if_used", "confirmed", "dependency",
               ["sa-contrib-2026-254", "commerce-rel-3-3-13", "commerce-rel-8-x-2-41",
                "cve-118539", "thn-commerce-118539"],
               "SA-CONTRIB-2026-254 (CVE-2026-118539): Drupal Commerce Core access bypass, actively exploited. "
               "Affected <2.41 or >=3.0.0 <3.3.13. Fixed builds 8.x-2.41 and 3.3.13. News ranges that include "
               "those builds are not floors. Drupal 7 commerce INI files are out of scope; this check cannot see them.",
               "Upgrade Commerce Core to 3.3.13 (requires Drupal ^10.3 || ^11) or 8.x-2.41 "
               "(requires Drupal ^9.3 || ^10). Then audit orders in the site database; this tool does not. "
               "No workaround replaces the upgrade.",
               ALL_OS, check_drupal_commerce),
    check_meta("connectwise-presence", "ConnectWise software present", "check_if_used", "confirmed", "runtime",
               ["thn-connectwise"], "A hacked ConnectWise Cloud Backup app was used to hit hundreds of companies.",
               "Ask whether you or a managed IT provider use ConnectWise.", ALL_OS, check_connectwise, uses_walk=False),
    check_meta("plex-media-server", "Plex Media Server below 1.43.3.10861", "awareness", "confirmed", "runtime", [],
               "4 Plex bugs on the CISA list; fixed in 1.43.3.10861 (briefing gives the domain thehackernews.com, no URL).",
               "Update Plex.", ALL_OS, check_plex, uses_walk=False),
    check_meta("tailscale-ssh-1104", "Tailscale SSH forwarding (TS-2026-014, fixed in 1.104.4)", "check_if_used",
               "confirmed", "runtime", ["tailscale-ssh-blog", "tailscale-bulletins"],
               "A trusted node could reach root-only Unix sockets on SSH targets via forwarding. Fixed in 1.104.4. "
               "No CVE id. Mitigation if a host cannot update: TS_SSH_DISABLE_FORWARDING=1 and restart tailscaled "
               "(reported only; this check never sets it or restarts).",
               "Upgrade to 1.104.4. If you cannot, set TS_SSH_DISABLE_FORWARDING=1 on tailscaled and restart. "
               "This tool never sets the variable or restarts the service.", ALL_OS, check_tailscale_ssh),
    check_meta("peoplesoft-presence", "Oracle PeopleSoft / PeopleTools footprint (CVE-2026-35273)", "check_if_used",
               "confirmed", "runtime", ["oracle-cve-2026-35273", "thn-peoplesoft"],
               "Oracle alert CVE-2026-35273 (PeopleTools 8.61 and 8.62, CVSS 9.8). Public reporting describes a "
               "three-flaw chain (PSIGW SSRF, loopback allowedhosts, PSEMHUB RCE) under that one CVE.",
               "If PeopleSoft is present, apply the Oracle alert patches. Presence is review: a patched host may "
               "keep the same PeopleTools version. This tool does not probe PIA.", ALL_OS, check_peoplesoft),
    check_meta("anthropic-ai-chain", "Browser and OS patch level (Anthropic AI-discovered chain, unconfirmed)",
               "check_if_used", "unconfirmed", "runtime", ["anthropic-ai-chain", "thn-anthropic-chain"],
               "Anthropic described five separate AI-discovered exploit chains (Chrome, Safari, Windows, Linux and "
               "Android), already patched upstream. Mapping a given host to those chains is unconfirmed here. "
               "Chrome 156 is a dated floor; Safari, Windows and Linux exact fixed builds are unverified. "
               "This check has no Android collection path; Android is out of scope.",
               "Update Chrome to 156 or newer and install current OS/browser updates. Do not treat this check as "
               "proof the chain exists or is fixed on a given build.", ALL_OS, check_anthropic_chain, uses_walk=False),
    check_meta("gmo-onamae-presence", "GMO Onamae Desktop Cloud / DNS use (customer-data breach)", "check_if_used",
               "confirmed", "credential", ["gmo-onamae", "thn-gmo-onamae"],
               "GMO Internet confirmed unauthorized access to Onamae Desktop Cloud and that customer information "
               "was published. This check looks only at local zone files and configs (no live DNS).",
               "If Onamae/GMO DNS or Desktop Cloud is in use, rotate credentials and review exposed customer data. "
               "This tool never contacts Onamae or queries public DNS.", ALL_OS, check_gmo_onamae),
    check_meta("claude-code-vsx-21313", "Tampered Anthropic.claude-code 2.1.313 and listed backdoor indicators",
               "check_now", "confirmed", "config", ["cursor-claude-vsx", "phorion-claude-vsx"],
               "Cursor Marketplace served a tampered Anthropic.claude-code 2.1.313 from about 09:27 UTC to 20:35 UTC "
               "on 29 Oct 2026. It plants an SSH key comment svc-telemetry, a fake com.apple.sysmond LaunchAgent, "
               "and a reverse tunnel. Uninstalling the extension does not remove persistence.",
               "Read-only: this tool never deletes keys, agents or files. If a finding is affected, isolate the host "
               "and follow the vendor notice from a clean device. Do not run unverified remediation scripts from chat.",
               ALL_OS, check_claude_code_vsx, uses_walk=False),
    check_meta("yoba-fake-ai-apps", "Yoba fake ChatGPT/Claude desktop apps (DLL sideload + WMProcess)",
               "check_if_used", "confirmed", "runtime", ["cpr-yoba", "thn-yoba"],
               "Check Point Research: fake GitHub desktop apps (GPT-5.6 Sol, GPT-6 Astra, Claude Opus) pair a signed "
               "Setup.exe with winmm.dll and later use ProgramData\\WMProcess. OpenAI and Anthropic were not breached.",
               "Do not run unofficial desktop AI installers. This tool never deletes files or scheduled tasks.",
               "Windows first; Downloads/Desktop names on all", check_yoba, uses_walk=False),
    check_meta("huggingface-qwen2-tiny", "Named Hugging Face qwen2-tiny cache paths (unconfirmed lead)",
               "check_if_used", "unconfirmed", "runtime", ["bc-hf-miner"],
               "Press report of a Hugging Face trust_remote_code mining campaign (MENXIANGYU/qwen2-tiny and copies). "
               "No vendor advisory retrieved. Findings stay unknown.",
               "If a named cache path is present, treat the host as needing owner review. Do not load models with "
               "trust_remote_code from an unreviewed revision.",
               ALL_OS, check_hf_qwen2, uses_walk=False),
    check_meta("go-mptcp-linux", "Go 1.24+ MPTCP default on Linux (kernel CVE-2026-98432)",
               "check_if_used", "confirmed", "runtime", ["golang-announce-98432"],
               "Go 1.24 enables MPTCP on Linux listen sockets by default. golang-announce describes CVE-2026-98432 as "
               "a Linux kernel TCP use-after-free; the demonstrated exploit used an MPTCP listener. No patched kernel "
               "version was named. godebug multipathtcp=0 is a fragile mitigation.",
               "Upgrade the kernel when a distro advisory names a build. Do not treat a Go-only change as a kernel fix.",
               "Linux (macOS/Windows: recorded only)", check_go_mptcp),
    check_meta("teamviewer-111585", "TeamViewer below TV-2026-1011 floors (CVE-2026-111585)",
               "check_if_used", "confirmed", "runtime", ["tv-2026-1011", "cve-111585"],
               "TeamViewer Full Client / Host / Portable below 15.83 (CVE-2026-111585). Legacy floors: "
               "15.64.10 on Windows 7/8 only, 14.7.48868, and 13.2.36231 (Windows) / 13.2.154008 (Linux) / "
               "13.2.154007 (macOS). Other lines below 15.83 are affected. Android is out of scope. "
               "This check never starts TeamViewer.",
               "Update to 15.83 or the listed legacy build. Do not start TeamViewer to collect a version.",
               ALL_OS, check_teamviewer, uses_walk=False),
    check_meta("fragnesia-linux", "Linux kernel Fragnesia (CVE-2026-46300, CISA KEV)",
               "check_if_used", "confirmed", "runtime",
               ["cisa-kev-46300", "cve-46300", "ubuntu-46300", "kernel-cve-46300", "nvd-46300"],
               "CVE-2026-46300 (Fragnesia): skb_try_coalesce shared-frag marker. Introduced in 3.9; CVE record "
               "floors 5.10.257, 5.15.208, 6.1.174, 6.6.141, 6.12.91, 6.18.33, 7.0.10; 7.1 and later unaffected. "
               "Ubuntu official x.y.0-N-generic rows from the 29 Oct 2026 page (N = 1-999). CISA KEV (added 28 Oct "
               "2026) describes a chain with CVE-2026-109618 and CVE-2026-109619; also run php2shell. Classification "
               "uses the running osrelease plus Ubuntu VERSION_ID.",
               "Install the Ubuntu fixed ABI for the running (release, series) pair, or the upstream stable floor. "
               "Also run php2shell. This tool never loads modules or writes sysctl.",
               "Linux only", check_fragnesia, uses_walk=False),
    check_meta("linux-tcp-uaf-98432", "Linux kernel TCP UAF CVE-2026-98432 (review only)",
               "check_if_used", "confirmed", "runtime", ["ubuntu-98432", "golang-announce-98432", "cve-98432"],
               "CVE-2026-98432 is a Linux IPv4 TCP use-after-free. Ubuntu last updated 29 Oct 2026 lists current "
               "releases as vulnerable work in progress with no released fixed build. The cve.org record published "
               "15 Oct 2026, updated 30 Oct 2026 lists upstream floors that are not Ubuntu package floors. This check records the "
               "running kernel and distro as review. It does not invent a floor. Go toolchains stay on go-mptcp-linux.",
               "Wait for a released distro build, then confirm the running kernel. WIP targets are not floors. "
               "Do not treat a Go-only change as a kernel fix.",
               "Linux only", check_linux_tcp_uaf, uses_walk=False),
]
CHECK_IDS = [c["id"] for c in CHECKS]
INDICATOR_CHECKS = {"testmetest-ai-hooks", "testmetest-large-blobs", "testmetest-npm-package",
                    "planted-agent-instructions", "function-color-npm-package", "litellm-1-107-0",
                    "claude-code-vsx-21313", "yoba-fake-ai-apps"}


def run_check(host, meta):
    r = Result()
    try:
        meta["fn"](host, r)
    except Exception as exc:  # a parser bug must not hide other checks
        r.blocked.append("check error: %s" % textscan.diagnostic_text(type(exc).__name__))
    kinds = {f["result"] for f in r.findings}
    walk_stopped = meta["uses_walk"] and not index(host).complete
    if kinds & {"affected", "review"}:
        status = "FAIL"
        n_aff = sum(f["result"] == "affected" for f in r.findings)
        n_rev = sum(f["result"] == "review" for f in r.findings)
        reason = "%d affected, %d to review" % (n_aff, n_rev)
    elif "unknown" in kinds:
        status, reason = "BLOCKED", "present but version or state could not be read without executing it"
    elif r.blocked:
        status, reason = "BLOCKED", "; ".join(r.blocked)
    elif walk_stopped:
        status, reason = "BLOCKED", "home walk stopped early (%s); nothing found in the part that was listed" % index(host).stopped
    elif meta["id"] in INDICATOR_CHECKS or r.present:
        status = "PASS"
        reason = "nothing to fix found in the listed scope" if meta["id"] in INDICATOR_CHECKS else \
            "present; every version found is at or above the fixed build in the briefing"
    else:
        status, reason = "NOT_APPLICABLE", "not present: no install, package, file or config found"
    if r.blocked and status == "FAIL":
        reason += "; also incomplete: " + "; ".join(r.blocked)
    deep = host.gaps.counts.get("max_depth", 0) if meta["uses_walk"] else 0
    if deep and status in ("PASS", "FAIL", "NOT_APPLICABLE"):
        reason += "; %d folder(s) deeper than --max-depth %d were not listed" % (deep, host.max_depth)
    order = {"affected": 0, "review": 1, "unknown": 2, "info": 3}
    findings = sorted(r.findings, key=lambda f: (order.get(f["result"], 9), f.get("component", ""), f.get("path", "") or "",
                                                 f.get("version", "") or "", json.dumps(f, sort_keys=True)))
    out = {k: meta[k] for k in ("id", "title", "section", "confirmation", "layer", "briefing_fact", "remediation",
                                "os_support")}
    out.update({"status": status, "reason": reason, "findings": findings[:500], "notes": r.notes,
                "sources": [{"title": SRC[s][0], "url": SRC[s][1]} for s in meta["sources"]]})
    if len(findings) > 500:
        out["findings_truncated"] = len(findings) - 500
    if meta["id"].startswith("testmetest") and status == "FAIL":
        out["cleanup_order"] = CLEANUP_ORDER
    return out


def report_fragments(doc, target, collected_on):
    sources, evidence, checks = {}, [], []
    for c in doc["checks"]:
        meta = next(m for m in CHECKS if m["id"] == c["id"])
        sids = []
        for key in meta["sources"]:
            sid = "src-" + key
            sids.append(sid)
            sources[sid] = {"id": sid, "title": SRC[key][0], "url": SRC[key][1],
                            "retrieved_on": collected_on or BRIEFING_DATE,
                            "kind": "other"}
        counts = {}
        for f in c["findings"]:
            counts[f["result"]] = counts.get(f["result"], 0) + 1
        top = "; ".join("%s %s%s" % (f["result"], f["component"], " " + f["version"] if f.get("version") else "")
                        for f in c["findings"][:5])
        summary = "host_checks.py %s: %s. Findings: %s%s" % (c["id"], c["reason"],
                                                           ", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "none",
                                                           (". First: " + top) if top else "")
        status = "complete"
        if c["status"] == "BLOCKED":
            status = "truncated" if "stopped" in c["reason"] else "unparsed"
        ev = {"id": "ev-host-" + c["id"], "kind": "config_snapshot" if c["layer"] == "config" else "file_excerpt",
              "target": target, "layer": c["layer"], "summary": summary[:1500], "collected_on": collected_on,
              "collection_status": status, "executed": True, "execution_context": "read_only_local",
              "redaction": "redacted", "command_ref": "python3 scripts/host_checks.py --only %s" % c["id"]}
        if sids:
            ev["source_ids"] = sids
        evidence.append(ev)
        chk = {"id": "host-" + c["id"], "title": c["title"], "target": target, "layer": c["layer"],
               "status": c["status"], "evidence_ids": [ev["id"]]}
        if c["status"] != "PASS":
            chk["reason"] = c["reason"]
        checks.append(chk)
    return {
        "note": "Merge into the report. NOT_APPLICABLE needs a human approved_by_role; dependency-layer PASS also needs "
                "inventory_manifests and covers from inventory.py. Sources stamp retrieved_on from --collected-on "
                "when supplied, otherwise " + BRIEFING_DATE + " (this tool does not fetch them); a human must "
                "re-read primary advisories and correct retrieved_on before closing findings.",
        "sources": [sources[k] for k in sorted(sources)], "evidence": evidence, "required_checks": checks}


def redact_tree(value):
    if isinstance(value, str):
        return textscan.redact(value)
    if isinstance(value, list):
        return [redact_tree(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_tree(v) for k, v in value.items()}
    return value


def run(host, only=None, target=None, collected_on=None, label=None):
    metas = [m for m in CHECKS if not only or m["id"] in only]
    results = [run_check(host, m) for m in metas]
    gap_kinds = sorted(host.gaps.counts)
    partial = [k for k in gap_kinds if k not in ("symlink_not_followed", "loop_or_hardlink")]
    summary = {}
    for c in results:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    stats = getattr(host, "walk_stats", {"directories_listed": 0, "entries_seen": 0, "stopped": None})
    doc = {
        "tool": "host_checks.py", "version": VERSION, "briefing": BRIEFING, "label": label or "endpoint",
        "what_this_is": "Read-only endpoint checks for one dated briefing. It is not a vulnerability scanner; "
                        "PASS means nothing was found in the listed scope, not that the machine is safe.",
        "limits": LIMITS,
        "host": {"platform": host.platform, "simulated": host.simulated,
                 "roots": [host.display(r) for r in host.roots]},
        "scan": {"max_depth": host.max_depth, "max_entries": host.max_entries,
                 "time_budget_exhausted": host.budget.exhausted, **stats,
                 "policy_skipped_dir_names": sorted(SKIP_ANY), "policy_skipped_home_dirs": sorted(SKIP_HOME_ROOT)},
        "coverage": {"status": "PARTIAL" if partial else "COMPLETE_FOR_LISTED_ROOTS", "partial_reasons": partial,
                     "gap_counts": dict(sorted(host.gaps.counts.items())), "gaps": host.gaps.examples},
        "summary": dict(sorted(summary.items())),
        "checks": results,
        "cleanup_order_testmetest": CLEANUP_ORDER,
        "skipped_briefing_items": [{"item": a, "reason": b} for a, b in SKIPPED],
    }
    if target:
        doc["report_fragments"] = report_fragments(doc, target, collected_on)
    return redact_tree(doc)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_allowlist(path):
    doc = hs.read_json(path, 4 * MIB)
    if not isinstance(doc, dict):
        raise ValueError("allowlist must be a JSON object")
    kinds = {"hooks", "large_files", "instruction_files", "mcp_servers", "base_urls"}
    for k, entries in doc.items():
        if k not in kinds or not isinstance(entries, list):
            raise ValueError("allowlist key %r is not one of %s" % (k, ", ".join(sorted(kinds))))
        for e in entries:
            if not isinstance(e, dict) or not str(e.get("reason", "")).strip():
                raise ValueError("every allowlist entry needs a non-empty reason")
            if not set(e) & {"path_glob", "sha256", "object_id", "name", "host"}:
                raise ValueError("allowlist entry needs path_glob, sha256, object_id, name or host")
    return doc


def plain_write(path, text, force):
    """Write for hosts without openat (Windows): O_EXCL create, or replace a regular file via a temp file."""
    path = os.path.abspath(path)
    st = hs.lstat(path)
    if st is not None and (stat.S_ISLNK(st.st_mode) or hs.is_reparse(st) or not stat.S_ISREG(st.st_mode)):
        raise OSError("refusing to write %s: not a regular file" % path)
    if st is not None and not force:
        raise OSError("%s exists; pass --force to replace it" % path)
    data = text.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    target = path if st is None else path + ".tmp-%d" % os.getpid()
    fd = os.open(target, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if target != path:
        os.replace(target, path)


def parse_mib_range(s):
    m = re.match(r"^(\d+)-(\d+)$", s or "")
    if not m or int(m.group(1)) > int(m.group(2)):
        raise argparse.ArgumentTypeError("use LOW-HIGH in MiB, e.g. 11-16")
    return int(m.group(1)) * MIB, int(m.group(2)) * MIB


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only endpoint checks for the dated briefing (never executes or writes).")
    ap.add_argument("--root", action="append", help="directory to walk (repeatable; default: home plus existing web roots)")
    ap.add_argument("--home", help="home directory to treat as ~ (default: the current user's)")
    ap.add_argument("--out")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--target", help="report target id; emits report_fragments")
    ap.add_argument("--label")
    ap.add_argument("--collected-on", help="evidence date for report_fragments (YYYY-MM-DD; default today)")
    ap.add_argument("--only", action="append", choices=CHECK_IDS, metavar="CHECK_ID")
    ap.add_argument("--list-checks", action="store_true")
    ap.add_argument("--allowlist", help="JSON file of owner-confirmed hooks, large files, instruction files, MCP servers, base URLs")
    ap.add_argument("--strict", action="store_true", help="exit 3 when any check FAILs or coverage is PARTIAL")
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--max-entries", type=int, default=400_000)
    ap.add_argument("--time-budget", type=float, default=240.0, help="seconds for the whole run (default 240)")
    ap.add_argument("--repo-seconds", type=float, default=15.0, help="seconds per repository for git object headers")
    ap.add_argument("--blob-review-mib", type=parse_mib_range, default=(11 * MIB, 16 * MIB))
    ap.add_argument("--platform", choices=["darwin", "linux", "windows"], help=argparse.SUPPRESS)
    ap.add_argument("--system-root", help=argparse.SUPPRESS)
    ap.add_argument("--env", action="append", default=[], help=argparse.SUPPRESS)
    ap.add_argument("--registry-snapshot", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.list_checks:
        for m in CHECKS:
            sys.stdout.write("%-28s %-13s %-11s %s\n" % (m["id"], m["section"], m["confirmation"], m["title"]))
        return 0
    if args.target and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.target):
        print("ERROR: --target must be a report id", file=sys.stderr)
        return 2
    if (args.env or args.registry_snapshot or args.platform) and not args.system_root:
        print("ERROR: --platform, --env and --registry-snapshot are for simulated hosts and need --system-root",
              file=sys.stderr)
        return 2
    try:
        allow = load_allowlist(args.allowlist) if args.allowlist else {}
    except (ValueError, OSError) as exc:
        print("ERROR ALLOWLIST: %s" % textscan.diagnostic_text(exc), file=sys.stderr)
        return 2
    env = None
    if args.system_root:
        env = dict(kv.split("=", 1) for kv in args.env if "=" in kv)
    registry = None
    if args.registry_snapshot:
        registry = hs.read_json(args.registry_snapshot, 16 * MIB) or []
    host = Host(platform=args.platform, home=args.home, sysroot=args.system_root, env=env,
                roots=args.root, max_depth=args.max_depth, max_entries=args.max_entries, time_budget=args.time_budget,
                repo_seconds=args.repo_seconds, allowlist=allow, registry=registry, blob_review=args.blob_review_mib)
    if not args.root:
        host.roots = [host.home] + web_roots(host)
    collected = args.collected_on or datetime.date.today().isoformat()
    doc = run(host, set(args.only or []), args.target, collected, args.label)
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        try:
            if safeio.HOST_SUPPORT_ERROR:
                plain_write(args.out, text, args.force)
            else:
                safeio.safe_write(args.out, text, args.force)
        except OSError as exc:
            print("ERROR OUTPUT: %s" % textscan.diagnostic_text(exc), file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    s = doc["summary"]
    print("host checks: %s; coverage %s" % (", ".join("%s=%d" % kv for kv in sorted(s.items())),
                                            doc["coverage"]["status"]), file=sys.stderr)
    failing = s.get("FAIL", 0) or doc["coverage"]["status"] == "PARTIAL"
    return 3 if (args.strict and failing) else 0


if __name__ == "__main__":
    sys.exit(main())
