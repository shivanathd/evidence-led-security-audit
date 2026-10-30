#!/usr/bin/env python3
"""Read-only local inventory of a repository or unpacked artifact.

This is an inventory, not a vulnerability scanner. It lists what exists so
the audit can decide which checks are required and what is out of reach.

It never executes, imports, builds or installs anything from the target,
never follows symlinks, never makes network calls, and never prints secret
values (only pattern name, path and line).

Coverage limits (also written into the output):
- Path and pattern heuristics only; no dependency resolution, no CVE matching.
- Does not inspect container images, running processes or remote services.
- Secret detection is pattern-based: binary, oversized and excluded files are
  not scanned, and novel formats are missed.
- scope_class (test_like, vendored, example) is path-based; the built image
  decides what actually ships.

Traversal is by directory file descriptor (see safeio): symlinked, swapped,
binary, special, oversized and excluded content is a coverage gap. Only a
human-recorded --accept-exclusion PATTERN=REASON turns a gap into an accepted
(still unscanned) exclusion. Needs POSIX openat support; otherwise BLOCKED.

Usage:
  python3 scripts/inventory.py ROOT [--out FILE [--force]] [--target ID]
      [--exclude-dir NAME ...] [--accept-exclusion PATTERN=REASON ...]
      [--max-files N] [--max-file-bytes N] [--strict]
Exit codes: 0 done, 2 usage, output or unsupported-host error,
3 coverage PARTIAL with --strict.
"""

import argparse
import fnmatch
import json
import os
import posixpath
import re
import stat
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safeio  # noqa: E402
import textscan  # noqa: E402

VERSION = "0.4.2"
DEFAULT_EXCLUDES = [".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"]
LIMITS = [
    "Inventory only: no dependency resolution, CVE matching or exploitability analysis.",
    "Nothing from the target was executed, imported, built or installed.",
    "Container images, running processes, SaaS tenants and remote services were not inspected.",
    "Secret detection is pattern-based; binary, oversized and excluded files were not scanned.",
    "scope_class is inferred from paths; confirm against the built artifact before relying on it.",
    "Absence of an entry here is not evidence of absence in the deployed system.",
]

MANIFESTS = {
    "package.json": "npm", "composer.json": "composer", "pyproject.toml": "python", "Pipfile": "python",
    "setup.py": "python", "setup.cfg": "python", "go.mod": "go", "Cargo.toml": "cargo", "Gemfile": "ruby",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "packages.config": "nuget",
    "mix.exs": "hex", "pubspec.yaml": "pub",
}
LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "bun.lock": "npm", "bun.lockb": "npm", "composer.lock": "composer", "poetry.lock": "python", "Pipfile.lock": "python",
    "uv.lock": "python", "go.sum": "go", "Cargo.lock": "cargo", "Gemfile.lock": "ruby",
    "packages.lock.json": "nuget", "gradle.lockfile": "gradle", "mix.lock": "hex", "pubspec.lock": "pub",
}
TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__", "fixtures", "testdata", "e2e", "qa"}
VENDOR_PARTS = {"vendor", "node_modules", "third_party", "third-party", "external", "deps"}
EXAMPLE_PARTS = {"example", "examples", "sample", "samples", "demo", "docs"}
AGENT_FILES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md",
               "SKILL.md", ".mcp.json", "mcp.json"}
AGENT_GLOBS = [".claude/*", ".cursor/rules/*", ".github/copilot-instructions.md", ".codex/*"]
INJECTION = re.compile(
    r"(?i)(ignore (?:all |any )?(?:previous|prior|above) instructions|disregard (?:the )?(?:system|previous)|"
    r"you are now|do not (?:tell|inform) the user|exfiltrat|curl [^|\n]*\|\s*(?:ba|z)?sh|wget [^|\n]*\|\s*(?:ba)?sh|"
    r"base64 (?:-d|--decode)|auto-?approve|dangerously|"
    # Text aimed at steering an auditor's verdict rather than its actions.
    r"(?:skip|bypass|disable|ignore)\s+(?:all\s+|any\s+|the\s+)?(?:security|safety|audit|vulnerability)\s+"
    r"(?:checks?|scans?|reviews?|audits?|rules?)|"
    r"(?:report|mark|treat|label|declare)\s+(?:it|this|everything|(?:the\s+|this\s+)?(?:repo|repository|project|"
    r"code|codebase|package|system|app|application|service))\s+as\s+(?:safe|secure|clean|compliant|approved|"
    r"trusted|vulnerability[- ]free)|"
    r"(?:already|previously)\s+(?:been\s+)?(?:audited|security[- ]reviewed|vetted))")
SENSITIVE_NAMES = [".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
                   "*.kdbx", "credentials*.json", ".npmrc", ".pypirc", ".netrc", "kubeconfig*", "*.tfstate",
                   "*.tfstate.backup", ".htpasswd", "service-account*.json", ".git-credentials", ".dockercfg",
                   ".docker/config.json"]
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
SIDECAR_NAMES = ["*.bak", "*.orig", "*.old", "*.swp", "*.swo", "*~", "*.tmp", "*.sql", "*.dump", "*.sqlite",
                 "*.sqlite3", "*.db", "*.log", ".DS_Store", "core", "core.[0-9]*", "*.har", "*.pcap", "*.pyc",
                 "*.heapsnapshot", "*.hprof"]
SIDECAR_DIRS = {"coverage", ".cache", "__pycache__", ".pytest_cache", "tmp", ".nyc_output", "logs"}
NPM_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}
COMPOSER_HOOKS = {"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-autoload-dump",
                  "post-root-package-install", "post-create-project-cmd"}
PHP_KEYS = ["memory_limit", "post_max_size", "upload_max_filesize", "session.upload_progress.enabled",
            "session.serialize_handler",
            "fatal_error_backtraces", "max_input_nesting_level", "max_input_vars", "pm.max_requests",
            "expose_php", "display_errors", "pm.status_path", "ping.path"]
PHP_SETTING = re.compile(
    r"^\s*(?:php_(?:admin_)?(?:value|flag)\s*(?:\[\s*)?)?(%s)(?:\s*\])?\s*[=\s]\s*([^\s;#]+)"
    % "|".join(re.escape(k) for k in PHP_KEYS))
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.IGNORECASE)
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
SETUP_NODE_RE = re.compile(r"(?i)(?:^|/)actions/setup-node(?:@|$)")
CI_NODE_VERSION_RE = re.compile(r"^\s*node-version:\s*['\"]?v?([^'\"\s#]+)")
PEOPLESOFT_PATH_PARTS = frozenset({"peoplesoft", "peopletools", "psft"})
PEOPLESOFT_FILENAMES = frozenset({
    "psconfig.sh", "allowedhosts.properties", "psappsrv.cfg", "psprcs.cfg",
})
COMMERCE_PROJECT_RE = re.compile(
    r"(?mi)^project:[ \t]*(?:'commerce'|\"commerce\"|commerce)[ \t]*(?:#.*)?$")
COMMERCE_PROJECT_ANY_RE = re.compile(r"(?mi)^project:[ \t]*")
COMMERCE_INFO_YML = "commerce" + ".info.yml"
COMMERCE_PKG_NAME_RE = re.compile(r'"name"\s*:\s*"drupal/commerce"')


def _commerce_normalize(text):
    return text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def _exists_nofollow(path):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _in_composer_vendor(file_path):
    """True when the file sits under a Composer vendor tree.

    A directory named vendor counts only if it contains autoload.php or
    composer/installed.json, so clients/vendor/acme/shop/composer.lock is
    not skipped.
    """
    current = os.path.dirname(os.path.abspath(file_path))
    while True:
        if os.path.basename(current).lower() == "vendor":
            return (
                _exists_nofollow(os.path.join(current, "autoload.php"))
                or _exists_nofollow(os.path.join(current, "composer", "installed.json"))
            )
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
# Split so the public-leak hostname scanner does not read a vendor domain as a leak.
_ONAMAE_LABEL = "onamae"
ONAMAE_HOST_RE = re.compile(r"(?i)\b(?:[\w-]+\.)?%s\.(?:com|co\.jp)\b" % _ONAMAE_LABEL)
ONAMAE_DNS_RE = re.compile(
    r"(?i)\b(?:NS|MX|nameserver)\b.*%s\.(?:com|co\.jp)|%s\.(?:com|co\.jp).*\b(?:NS|MX|nameserver)" %
    (_ONAMAE_LABEL, _ONAMAE_LABEL))
GMO_DNS_NAMES = frozenset({"named.conf", "named.conf.local"})
# ${{ ... }} blocks, then github.event / head_ref / ref_name refs inside them.
# Safe leaf fields (.number / .id / .state / .draft) are excluded per-reference so
# `github.event.issue.number && github.event.issue.title` still flags the title.
GHA_INTERP = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)
GHA_UNTRUSTED_REF = re.compile(
    r"github\.(?:head_ref|ref_name|event\.(?:issue|comment|pull_request|"
    r"review|discussion|review_comment|discussion_comment|commits?|head_commit|"
    r"release|client_payload)(?:\.[A-Za-z_][\w]*|\[['\"][^'\"]+['\"]])*)",
    re.IGNORECASE)
GHA_SAFE_LEAF = frozenset({"number", "id", "state", "draft"})


def _gha_ref_leaf(ref):
    br = re.search(r"\[['\"]([^'\"]+)['\"]\]\s*$", ref)
    if br:
        return br.group(1)
    return ref.rsplit(".", 1)[-1]


def untrusted_gha_refs(text):
    """Return untrusted github.* refs interpolated inside ${{ }} expressions."""
    hits = []
    for block in GHA_INTERP.finditer(text or ""):
        for m in GHA_UNTRUSTED_REF.finditer(block.group(1)):
            ref = m.group(0)
            if _gha_ref_leaf(ref).lower() in GHA_SAFE_LEAF:
                continue
            hits.append(ref)
    return hits
NGINX_LISTEN = re.compile(r"^\s*listen\s+([^;]+);")
FPM_LISTEN = re.compile(r"^\s*listen\s*=\s*(\S+)")
APACHE_LISTEN = re.compile(r"^\s*Listen\s+(\S+)")
# Serving PHP packages and official images. Bare "php" plus a letter
# (phpmyadmin, phpunit, phpstan) is not a match; a version or SAPI suffix is.
# Arch/openSUSE: php-fpm / php-cgi / php-legacy / apache2-mod_php*. The
# unversioned Arch package name "php" is not an inventory token (it collides
# with application names); query it on the host via pacman, not this regex.
PHP_SAPI_PKG = re.compile(
    r"(?i)\b(php-fpm|php-cgi|php-embed|php-legacy(?:-fpm|-cgi|-apache)?|"
    r"php\d+(?:\.\d+)?(?:-fpm|-cli|-cgi|-common)?|"
    r"libapache2-mod-php\S*|apache2-mod_php\S*|lsphp\d*|frankenphp)\b"
)
# Path-segment match: name is a whole image path component. Delimiters are
# :, / or @ (or end). A trailing hyphen is not a delimiter, so
# prom/node-exporter, python-builder, myorg/python-app and phpmyadmin do not match.
RUNTIME_IMAGE = re.compile(
    r"(?i)(?:^|/)(?:node(?:js)?|javascript-node|bun|python|"
    r"envoy(?:proxy)?|istio|nginx(?:inc)?|openresty|"
    r"php(?:-fpm)?)(?:[:/@]|$)"
)
PHP_IMAGE = re.compile(r"(?i)(?:^|/)(?:php(?:-fpm)?)(?:[:/@]|$)")
MESH_VPN_IMAGE = re.compile(
    r"(?i)(?:^|/)(?:tailscale|headscale|zerotier|netbird(?:io)?)(?:[:/@]|$)"
)
MESH_VPN_PKG = re.compile(r"(?i)\b(tailscale|headscale|zerotier(?:-one)?|netbird)\b")
MESH_VPN_SERVICES = frozenset({"tailscale", "headscale", "zerotier", "netbird"})
MESH_VPN_PATH_PARTS = frozenset({"tailscale", "headscale", "zerotier", "zerotier-one", "netbird"})
# Filename-only mesh policy/config. Generic ACL names (acl.json, acl.js) are
# Casbin/app stubs too often; those need a content check, not a name match.
MESH_VPN_FILENAMES = frozenset({
    "acl.hujson", "policy.hujson",
    "headscale.yaml", "headscale.yml", "tailscale-acl.json", "tailnet-acl.json",
    "tailnet-policy.json", "netbird.yml", "netbird.yaml",
})
MESH_VPN_GENERIC_ACL_NAMES = frozenset({"acl.json", "acl.js"})
RUNTIME_PIN_FILES = {
    ".nvmrc": "node", ".node-version": "node", ".python-version": "python",
    ".ruby-version": "ruby", ".bun-version": "bun", ".tool-versions": "asdf",
    ".mise.toml": "mise", "mise.toml": "mise",
}
SBOM_EXACT = {"bom.json", "sbom.json", "cyclonedx.json"}
SBOM_SUFFIXES = (".cdx.json", ".spdx.json", ".spdx")
DEV_SERVER_PACKAGES = ("@vitest/ui", "vite-plus", "webpack-dev-server", "vitest", "vite")
DEV_SERVER_LOCK_RE = re.compile(
    r"(?i)(?:^|[\"'/\s])(?:node_modules/)?"
    r"(?P<pkg>@vitest/ui|vite-plus|webpack-dev-server|vitest|vite)"
    r"(?:[\"'@:]|\s|$)"
)
DEV_SERVER_BIND_RE = re.compile(
    r"(?i)(?:--ui\b|--api\b|\bapi\s*:\s*(?:true|\{)|browserMode\b|Browser Mode|server\.host\b)"
)
DEV_SERVER_CONFIG_RE = re.compile(r"^(?:vite|vitest|webpack)\.config\.[cm]?[jt]sx?$")


def is_runtime_image(ref):
    """True when a FROM ref looks like a Node, Python, Bun, Envoy, Istio, nginx-family or official PHP image."""
    return bool(ref) and bool(RUNTIME_IMAGE.search(ref))


def is_php_image(ref):
    """True for official php / php-fpm image refs, not phpmyadmin or php-app names.

    Tags such as php:8.3-fpm-alpine and php:8.2-apache match. Repo names
    php-apache and webdevops/php-apache do not (hyphenated image name, not
    the official php: tag).
    """
    if not ref:
        return False
    lower = ref.lower()
    if "frankenphp" in lower or "litespeed" in lower:
        return True
    return bool(PHP_IMAGE.search(ref))


def is_mesh_vpn_image(ref):
    """True for Tailscale, Headscale, ZeroTier or NetBird image refs."""
    return bool(ref) and bool(MESH_VPN_IMAGE.search(ref))


def is_php_package_token(token):
    """True for distro PHP runtime packages, not phpmyadmin.

    Covers Debian/Ubuntu (php8.3, php-fpm, libapache2-mod-php), Alpine
    (php83, php85), Arch SAPI packages (php-fpm, php-cgi, php-legacy), and
    openSUSE (php8, apache2-mod_php8). The unversioned Arch package name
    ``php`` and image repos ``php-apache`` / ``webdevops/php-apache`` are
    out of scope for this token (they collide with application names).
    """
    return bool(token) and bool(PHP_SAPI_PKG.search(token))


# HuJSON-aware scan of mesh SSH policy. Bounded so a huge file cannot
# turn this heuristic into an unbounded walk. Inventory already skips
# files above --max-file-bytes; this is an extra cap on tokenizing.
MESH_POLICY_SCAN_LIMIT = 262144
_MESH_POLICY_OTHER = frozenset({"acls", "grants", "nodeAttrs", "groups"})
_MESH_RULE_MEMBERS = frozenset({"action", "src", "dst"})
_HUJSON_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HUJSON_NUM = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


def _hujson_tokens(text, limit=MESH_POLICY_SCAN_LIMIT):
    """Tokenize JSON/HuJSON: comments, double-quoted strings, trailing commas.

    Yields (kind, value) where kind is str, ident, num, or punct. Skips
    whitespace and // /* */ comments outside strings. Single quotes are
    not string delimiters. Input longer than *limit* is truncated.
    """
    if not text:
        return []
    if len(text) > limit:
        text = text[:limit]
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            i = n if nl < 0 else nl + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if c == '"':
            i += 1
            buf = []
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                buf.append(ch)
                i += 1
            tokens.append(("str", "".join(buf)))
            continue
        ident = _HUJSON_IDENT.match(text, i)
        if ident:
            tokens.append(("ident", ident.group(0)))
            i = ident.end()
            continue
        num = _HUJSON_NUM.match(text, i)
        if num:
            tokens.append(("num", num.group(0)))
            i = num.end()
            continue
        if c in "{}[],:":
            tokens.append(("punct", c))
        i += 1
    return tokens


def _token_name(tok):
    if tok[0] in ("str", "ident"):
        return tok[1]
    return None


def _value_end(tokens, start):
    """Index after the value starting at start. Scalars consume one token."""
    n = len(tokens)
    if start >= n:
        return start
    kind, value = tokens[start]
    if not (kind == "punct" and value in "{["):
        return start + 1
    depth = 0
    i = start
    while i < n:
        k, v = tokens[i]
        if k == "punct":
            if v in "{[":
                depth += 1
            elif v in "}]":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return n


def _colon_keys(tokens, start, end):
    names = set()
    i = start
    while i + 1 < end:
        name = _token_name(tokens[i])
        nxt = tokens[i + 1]
        if name is not None and nxt[0] == "punct" and nxt[1] == ":":
            names.add(name)
            i += 2
            continue
        i += 1
    return names


def _member_names(tokens, start, end):
    """Object member names: `name:` keys or bare `{action, src}` identifiers."""
    names = _colon_keys(tokens, start, end)
    i = start
    while i < end:
        name = _token_name(tokens[i])
        if name is not None and i > start and i + 1 < end:
            prev, nxt = tokens[i - 1], tokens[i + 1]
            if (
                prev[0] == "punct" and prev[1] in "{,"
                and nxt[0] == "punct" and nxt[1] in ",}"
            ):
                names.add(name)
        i += 1
    return names


def _is_port_only_object(tokens, start, end):
    if start >= end or tokens[start] != ("punct", "{"):
        return False
    names = _member_names(tokens, start, end)
    return bool(names) and names <= {"port"}


def _looks_like_mesh_policy(text):
    """True for a JSON/HuJSON mesh SSH policy, not a service ssh port object.

    The `ssh` key must have a `{...}` or `[...]` value (comments between
    `ssh:` and the value are skipped). That value is a hit when it is
    rule-shaped (`action` / `src` / `dst` members) or when it is an
    object/array and the file also has `acls` / `grants` / `nodeAttrs` /
    `groups`. A `{port: N}`-only object is never a hit.
    """
    tokens = _hujson_tokens(text)
    if not tokens:
        return False
    has_other = bool(_colon_keys(tokens, 0, len(tokens)) & _MESH_POLICY_OTHER)
    i = 0
    n = len(tokens)
    while i + 1 < n:
        name = _token_name(tokens[i])
        if name == "ssh" and tokens[i + 1] == ("punct", ":"):
            val_i = i + 2
            if val_i >= n or tokens[val_i][0] != "punct" or tokens[val_i][1] not in "{[":
                i += 1
                continue
            val_end = _value_end(tokens, val_i)
            if _is_port_only_object(tokens, val_i, val_end):
                i = val_end
                continue
            members = _member_names(tokens, val_i, val_end)
            if _MESH_RULE_MEMBERS <= members or has_other:
                return True
            i = val_end
            continue
        i += 1
    return False


def _is_sbom(name):
    lower = name.lower()
    if lower in SBOM_EXACT or lower.endswith(SBOM_SUFFIXES):
        return True
    if not lower.endswith((".json", ".xml")):
        return False
    stem = lower.rsplit(".", 1)[0]
    return stem == "sbom" or stem.endswith("-sbom") or stem.endswith("_sbom") or stem.endswith(".sbom")


def classify(rel):
    parts = {p.lower() for p in PurePosixPath(rel).parts[:-1]}
    if parts & VENDOR_PARTS:
        return "vendored"
    if parts & TEST_PARTS:
        return "test_like"
    if parts & EXAMPLE_PARTS:
        return "example"
    return "runtime"


def _match(name, rel, patterns):
    return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(rel, p) for p in patterns)


ACCEPTABLE_GAPS = {"symlink_not_followed", "binary_not_scanned", "excluded_dir", "not_regular", "too_large"}


class Inventory:
    def __init__(self, root, excludes, max_files, max_bytes, accepted=()):
        self.root = root
        self.excludes = set(excludes)
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.accepted = list(accepted)  # [(pattern, reason)] recorded by a human
        self.gaps = {}
        self.gap_paths = []
        self.accepted_hits = {}
        self.files_seen = 0
        self.files_read = 0
        self.max_reached = False
        self.out = {k: [] for k in ("manifests", "containers", "listeners", "php_runtime_hints", "runtime_hints",
                                    "runtime_pins", "sboms", "dev_server_hints", "mesh_vpn_hints",
                                    "peoplesoft_hints", "gmo_onamae_hints", "drupal_commerce_hints",
                                    "install_hooks", "ci_workflows", "agent_instruction_files",
                                    "secret_candidates", "sensitive_filenames", "sidecar_artifacts",
                                    "symlinks")}

    def skip(self, rel, reason):
        """Record a coverage gap; only listed kinds can match an accepted exclusion."""
        if reason in ACCEPTABLE_GAPS:
            for pattern, _why in self.accepted:
                if fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(rel + "/", pattern):
                    self.accepted_hits.setdefault(pattern, []).append({"path": rel, "reason": reason})
                    return
        self.gaps[reason] = self.gaps.get(reason, 0) + 1
        if len(self.gap_paths) < 200:
            self.gap_paths.append({"path": rel, "reason": reason})

    def walk(self):
        prune = lambda rel, name: name in self.excludes  # noqa: E731
        for kind, rel, dfd, name, st in safeio.walk(self.root, prune):
            if kind == "dir":
                if name in SIDECAR_DIRS:
                    self.out["sidecar_artifacts"].append({"path": rel + "/", "reason": "cache, log or coverage directory"})
                continue
            if kind == "excluded_dir":
                if name in SIDECAR_DIRS:
                    self.out["sidecar_artifacts"].append({"path": rel + "/", "reason": "cache, log or coverage directory"})
                self.skip(rel + "/", "excluded_dir")
                continue
            if kind == "symlink":
                self._symlink(dfd, name, rel)
                continue
            if kind != "file":
                self.skip(rel, "not_regular" if kind == "special" else kind)
                continue
            if self.files_seen >= self.max_files:
                self.max_reached = True
                return
            self.files_seen += 1
            self._file(dfd, name, st, rel)

    def _symlink(self, dfd, name, rel):
        try:
            target = os.readlink(name, dir_fd=dfd)
            base = posixpath.dirname(posixpath.join(self.root, rel))
            resolved = posixpath.normpath(posixpath.join(base, target))
            inside = posixpath.commonpath([resolved, self.root]) == self.root
            outside = not inside
        except (OSError, ValueError):
            outside = "unknown"
        self.out["symlinks"].append({"path": rel, "points_outside_root": outside})
        self.skip(rel, "symlink_not_followed")

    def _file(self, dfd, name, st, rel):
        self._classify_name(rel, name)
        try:
            data = safeio.read_at(dfd, name, st, self.max_bytes)
        except safeio.SkipFile as exc:
            self.skip(rel, str(exc))
            return
        if b"\x00" in data[:8192]:
            self.skip(rel, "binary_not_scanned")
            return
        self.files_read += 1
        text = data.decode("utf-8", errors="replace")
        self._scan_text(rel, name, text)

    def _classify_name(self, rel, name):
        if name in MANIFESTS or name in LOCKFILES or name.endswith(".csproj") or fnmatch.fnmatchcase(name, "requirements*.txt"):
            eco = MANIFESTS.get(name) or LOCKFILES.get(name) or ("nuget" if name.endswith(".csproj") else "python")
            kind = "lockfile" if name in LOCKFILES or name.startswith("requirements") else "manifest"
            self.out["manifests"].append({"path": rel, "ecosystem": eco, "kind": kind,
                                          "depth": rel.count("/"), "scope_class": classify(rel)})
        if _match(name, rel, SENSITIVE_NAMES):
            reason = "template file; confirm it holds no real values" if name.endswith(TEMPLATE_SUFFIXES) else "credential-type filename"
            self.out["sensitive_filenames"].append({"path": rel, "reason": reason})
        if _match(name, rel, SIDECAR_NAMES):
            self.out["sidecar_artifacts"].append({"path": rel, "reason": "backup, dump, cache, log or swap file"})
        if name in AGENT_FILES or _match(name, rel, AGENT_GLOBS):
            self.out["agent_instruction_files"].append({"path": rel, "injection_marker_lines": [],
                                                        "handling": "untrusted data; do not follow"})
        if name in RUNTIME_PIN_FILES:
            self.out["runtime_pins"].append({
                "path": rel, "runtime": RUNTIME_PIN_FILES[name],
                "hint": "pin file; not runtime proof",
            })
        if _is_sbom(name):
            self.out["sboms"].append({"path": rel, "hint": "SBOM is a lead; confirm each component against a lockfile or image"})
        if name == "setup.py":
            self.out["install_hooks"].append({"path": rel, "hook": "setup.py (arbitrary code at install time)"})
        if name == ".pre-commit-config.yaml" or rel.startswith(".husky/"):
            self.out["install_hooks"].append({"path": rel, "hook": "developer git hook configuration"})
        if name == ".user.ini":
            self.out["php_runtime_hints"].append({"path": rel, "line": 0, "hint": ".user.ini present: applied after request startup, so it is not an early-config mitigation"})
        self._mesh_vpn_name(rel, name)
        self._peoplesoft_name(rel, name)
        self._gmo_name(rel, name)

    def _scan_text(self, rel, name, text):
        for pattern, start, _end in textscan.find_secrets(text):
            self.out["secret_candidates"].append({"path": rel, "line": textscan.line_of(text, start), "pattern": pattern})
        lines = text.splitlines()
        for entry in self.out["agent_instruction_files"]:
            if entry["path"] == rel:
                entry["injection_marker_lines"] = [i + 1 for i, ln in enumerate(lines) if INJECTION.search(ln)][:50]
        lower = name.lower()
        if lower.startswith(("dockerfile", "containerfile")) or lower.endswith(".dockerfile"):
            self._dockerfile(rel, lines)
        if re.match(r"(docker-)?compose.*\.ya?ml$", lower):
            self._compose(rel, lines)
        if lower.endswith((".conf", ".ini", ".htaccess")) or lower in (".htaccess", ".user.ini", "httpd.conf"):
            self._server_conf(rel, lines)
        if rel.startswith(".github/workflows/") or lower == ".gitlab-ci.yml":
            self._ci(rel, lines, text)
        if name == "package.json":
            self._json_hooks(rel, text, "scripts", NPM_HOOKS)
            self._package_engines(rel, text)
            self._dev_server_package_json(rel, text)
        if name == "composer.json":
            self._json_hooks(rel, text, "scripts", COMPOSER_HOOKS)
            self._composer_php(rel, text)
        if name == "composer.lock":
            self._composer_lock_php(rel, text)
            self._composer_lock_commerce(rel, text)
        self._commerce_info_yml(rel, name, text)
        if name in LOCKFILES and LOCKFILES[name] == "npm":
            self._dev_server_lockfile(rel, text)
        self._mesh_vpn_text(rel, name, text)
        self._peoplesoft_text(rel, name, text)
        self._gmo_text(rel, name, text)
        if DEV_SERVER_CONFIG_RE.match(name):
            self._dev_server_config(rel, lines)
        if lower.endswith(".php"):
            for i, ln in enumerate(lines):
                if "phpinfo(" in ln:
                    self.out["php_runtime_hints"].append({"path": rel, "line": i + 1, "hint": "phpinfo() call; must not be reachable publicly"})

    def _dockerfile(self, rel, lines):
        stages, froms, expose, user = set(), [], [], None
        for i, ln in enumerate(lines):
            m = FROM_RE.match(ln)
            if m:
                ref = m.group(1)
                if ref.lower() != "scratch" and ref not in stages:
                    froms.append({"line": i + 1, "image": ref, "pinned_digest": "@sha256:" in ref})
                    if is_php_image(ref):
                        self.out["php_runtime_hints"].append({"path": rel, "line": i + 1, "hint": "PHP base image %s (tag is a hint, not runtime proof)" % ref})
                    elif is_runtime_image(ref):
                        self.out["runtime_hints"].append({
                            "path": rel, "line": i + 1,
                            "hint": "runtime or proxy base image %s (tag is a hint, not runtime proof)" % ref,
                        })
                    if is_mesh_vpn_image(ref):
                        self.out["mesh_vpn_hints"].append({
                            "path": rel, "line": i + 1,
                            "hint": "mesh VPN base image %s (tag is a hint, not runtime proof)" % ref,
                        })
                if m.group(2):
                    stages.add(m.group(2))
            m = EXPOSE_RE.match(ln)
            if m:
                for port in m.group(1).split():
                    expose.append(port)
                    self.out["listeners"].append({"path": rel, "line": i + 1, "source": "EXPOSE", "value": port})
            if re.match(r"^\s*USER\s+", ln, re.IGNORECASE):
                user = ln.split(None, 1)[1].strip() if len(ln.split(None, 1)) > 1 else ""
            if not ln.lstrip().startswith("#"):
                for pm in PHP_SAPI_PKG.finditer(ln):
                    self.out["php_runtime_hints"].append({"path": rel, "line": i + 1, "hint": "package or SAPI reference %s" % pm.group(1)})
                if re.match(r"^\s*RUN\s+", ln, re.IGNORECASE):
                    seen = []
                    for pm in MESH_VPN_PKG.finditer(ln):
                        name = pm.group(1).lower()
                        if name in seen:
                            continue
                        seen.append(name)
                        self.out["mesh_vpn_hints"].append({
                            "path": rel, "line": i + 1,
                            "hint": "Dockerfile installs mesh VPN package %s (install line; not runtime proof)" % pm.group(1),
                        })
        self.out["containers"].append({"path": rel, "from": froms, "expose": expose,
                                       "user": user if user is not None else "not set (defaults to image user, often root)"})

    def _compose(self, rel, lines):
        ports_indent = None
        for i, ln in enumerate(lines):
            if not ln.strip() or ln.strip().startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip())
            svc = re.match(r"^(\s*)([A-Za-z0-9._-]+):\s*$", ln)
            if svc and svc.group(2).lower() in MESH_VPN_SERVICES:
                self.out["mesh_vpn_hints"].append({
                    "path": rel, "line": i + 1,
                    "hint": "compose service %s (service name; confirm the image and whether the daemon is enabled)" % svc.group(2),
                })
            img = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", ln)
            if img and is_mesh_vpn_image(img.group(1)):
                self.out["mesh_vpn_hints"].append({
                    "path": rel, "line": i + 1,
                    "hint": "compose mesh VPN image %s (tag is a hint, not runtime proof)" % img.group(1),
                })
            if re.match(r"^\s*ports:\s*$", ln):
                ports_indent = indent
                continue
            if ports_indent is not None:
                if indent > ports_indent and ln.strip().startswith("-"):
                    value = ln.strip()[1:].strip().strip("'\"")
                    self.out["listeners"].append({"path": rel, "line": i + 1, "source": "compose_ports", "value": value})
                    continue
                ports_indent = None

    def _server_conf(self, rel, lines):
        for i, ln in enumerate(lines):
            for rx, src in ((NGINX_LISTEN, "nginx_listen"), (FPM_LISTEN, "fpm_listen"), (APACHE_LISTEN, "apache_listen")):
                m = rx.match(ln)
                if m:
                    self.out["listeners"].append({"path": rel, "line": i + 1, "source": src, "value": m.group(1).strip()})
            m = PHP_SETTING.match(ln)
            if m:
                self.out["php_runtime_hints"].append({"path": rel, "line": i + 1,
                                                      "hint": "setting %s = %s (file value; effective runtime value may differ)" % (m.group(1), m.group(2))})

    def _ci_untrusted_run(self, lines):
        """Flag github.event / head_ref interpolations that sit in a run: script.

        env: BODY: ${{ github.event.issue.body }} is the documented safer pattern and is
        not listed. Numeric fields (.number, .id, .state, .draft) are not listed.
        """
        hits = []
        run_indent = None
        for i, ln in enumerate(lines):
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip())
            if run_indent is not None and indent <= run_indent:
                run_indent = None
            m = re.match(r"^(\s*)(- )?run:\s*(.*)$", ln)
            if m:
                rest = m.group(3)
                # Key indent includes the "- " prefix so a same-level env: ends the block.
                run_indent = len(m.group(1)) + (2 if m.group(2) else 0)
                if rest and rest not in ("|", ">", ">-", "|-", "|+", ">+"):
                    for ref in untrusted_gha_refs(rest):
                        hits.append({"line": i + 1, "expr": ref})
                continue
            if run_indent is not None and indent > run_indent:
                for ref in untrusted_gha_refs(ln):
                    hits.append({"line": i + 1, "expr": ref})
        return hits[:50]

    def _ci(self, rel, lines, text):
        unpinned = []
        for i, ln in enumerate(lines):
            m = USES_RE.match(ln)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "docker://")):
                continue
            if "@" not in ref or not re.fullmatch(r"[0-9a-f]{40}", ref.rsplit("@", 1)[1]):
                unpinned.append({"line": i + 1, "ref": ref})
        entry = {
            "path": rel, "unpinned_actions": unpinned,
            "pull_request_target": "pull_request_target" in text,
            "remote_script_piped_to_shell": bool(re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh", text)),
            "secrets_references": len(re.findall(r"\$\{\{\s*secrets\.", text)),
        }
        if rel.startswith(".github/workflows/"):
            entry["untrusted_run_interpolations"] = self._ci_untrusted_run(lines)
        self.out["ci_workflows"].append(entry)
        for i, ln in enumerate(lines):
            m = USES_RE.match(ln)
            if not m or not SETUP_NODE_RE.search(m.group(1)):
                continue
            for j in range(i + 1, min(i + 16, len(lines))):
                nxt = lines[j]
                if re.match(r"^\s*-\s+", nxt) and j > i + 1:
                    break
                vm = CI_NODE_VERSION_RE.match(nxt)
                if vm:
                    self.out["runtime_hints"].append({
                        "path": rel, "line": j + 1,
                        "hint": "CI setup-node %s (workflow pin, not runtime proof)" % vm.group(1),
                    })
                    break
                if re.match(r"^\s*node-version-file:", nxt):
                    self.out["runtime_hints"].append({
                        "path": rel, "line": j + 1,
                        "hint": "CI setup-node node-version-file (pin file is the runtime proof, not this line)",
                    })
                    break

    def _json_hooks(self, rel, text, key, hooks):
        try:
            doc = json.loads(text)
        except ValueError:
            self.skip(rel, "unparsed_json")
            return
        scripts = doc.get(key) if isinstance(doc, dict) else None
        if isinstance(scripts, dict):
            for h in sorted(set(scripts) & hooks):
                self.out["install_hooks"].append({"path": rel, "hook": "%s script (not executed)" % h})

    def _package_engines(self, rel, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        engines = doc.get("engines") if isinstance(doc, dict) else None
        if isinstance(engines, dict) and isinstance(engines.get("node"), str):
            self.out["runtime_hints"].append({
                "path": rel, "line": 0,
                "hint": "package.json engines.node %s (source constraint, not runtime proof)" % engines["node"],
            })

    def _dev_server_package_json(self, rel, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        names = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            block = doc.get(key)
            if isinstance(block, dict):
                names.update(block)
        for pkg in DEV_SERVER_PACKAGES:
            if pkg in names:
                self.out["dev_server_hints"].append({
                    "path": rel, "line": 0,
                    "hint": "test-runner or bundler package %s (manifest entry; not a listen proof)" % pkg,
                })
        scripts = doc.get("scripts")
        if isinstance(scripts, dict):
            for script, cmd in scripts.items():
                if isinstance(cmd, str) and DEV_SERVER_BIND_RE.search(cmd):
                    self.out["dev_server_hints"].append({
                        "path": rel, "line": 0,
                        "hint": "package.json script %s has a dev-server bind flag" % script,
                    })

    def _dev_server_lockfile(self, rel, text):
        seen = []
        for match in DEV_SERVER_LOCK_RE.finditer(text):
            pkg = match.group("pkg")
            if pkg in seen:
                continue
            seen.append(pkg)
            self.out["dev_server_hints"].append({
                "path": rel, "line": textscan.line_of(text, match.start()),
                "hint": "test-runner or bundler package %s (lockfile entry; not a listen proof)" % pkg,
            })
            if len(seen) >= 8:
                break

    def _dev_server_config(self, rel, lines):
        for i, ln in enumerate(lines):
            if DEV_SERVER_BIND_RE.search(ln):
                self.out["dev_server_hints"].append({
                    "path": rel, "line": i + 1,
                    "hint": "dev-server bind flag in config (configured listen; confirm on the running host)",
                })

    def _composer_php(self, rel, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        for key in ("require", "require-dev"):
            block = doc.get(key)
            if isinstance(block, dict) and isinstance(block.get("php"), str):
                self.out["php_runtime_hints"].append({
                    "path": rel, "line": 0,
                    "hint": "composer.json %s.php %s (source constraint, not runtime proof)" % (key, block["php"]),
                })
        cfg = doc.get("config")
        platform = cfg.get("platform") if isinstance(cfg, dict) else None
        if isinstance(platform, dict) and isinstance(platform.get("php"), str):
            self.out["php_runtime_hints"].append({
                "path": rel, "line": 0,
                "hint": "composer.json config.platform.php %s (source constraint, not runtime proof)" % platform["php"],
            })

    def _composer_lock_php(self, rel, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        for key in ("platform", "platform-overrides"):
            block = doc.get(key)
            if isinstance(block, dict) and isinstance(block.get("php"), str):
                self.out["php_runtime_hints"].append({
                    "path": rel, "line": 0,
                    "hint": "composer.lock %s.php %s (lock constraint, not runtime proof)" % (key, block["php"]),
                })

    def _composer_lock_commerce(self, rel, text):
        if _in_composer_vendor(os.path.join(self.root, rel)):
            return
        text = _commerce_normalize(text)
        try:
            doc = json.loads(text)
        except ValueError:
            return
        blocks = []
        if isinstance(doc, list):
            blocks = [doc]
        elif isinstance(doc, dict):
            for key in ("packages", "packages-dev"):
                block = doc.get(key)
                if isinstance(block, list):
                    blocks.append(block)
        for block in blocks:
            for pkg in block:
                if isinstance(pkg, dict) and pkg.get("name") == "drupal/commerce":
                    self.out["drupal_commerce_hints"].append({
                        "path": rel, "line": 0,
                        "hint": "composer.lock package drupal/commerce (lock pin; not runtime proof)",
                    })
                    return
        if COMMERCE_PKG_NAME_RE.search(text):
            self.out["drupal_commerce_hints"].append({
                "path": rel, "line": 0,
                "hint": "composer.lock names drupal/commerce (lock pin; not runtime proof)",
            })

    def _commerce_info_yml(self, rel, name, text):
        if name.lower() != COMMERCE_INFO_YML:
            return
        if _in_composer_vendor(os.path.join(self.root, rel)):
            return
        text = _commerce_normalize(text)
        if COMMERCE_PROJECT_RE.search(text):
            self.out["drupal_commerce_hints"].append({
                "path": rel, "line": 0,
                "hint": "Drupal Commerce Core " + COMMERCE_INFO_YML + " (packaged metadata; not runtime proof)",
            })
            return
        if COMMERCE_PROJECT_ANY_RE.search(text):
            self.out["drupal_commerce_hints"].append({
                "path": rel, "line": 0,
                "hint": COMMERCE_INFO_YML + " names a different project (not runtime proof)",
            })
            return
        self.out["drupal_commerce_hints"].append({
            "path": rel, "line": 0,
            "hint": "unpackaged Commerce checkout (no project: key; not runtime proof)",
        })

    def _peoplesoft_name(self, rel, name):
        lower = name.lower()
        parts = {p.lower() for p in PurePosixPath(rel).parts}
        if parts & PEOPLESOFT_PATH_PARTS or lower in PEOPLESOFT_FILENAMES:
            if lower == "configuration.properties" and not (parts & PEOPLESOFT_PATH_PARTS or "pia" in parts):
                return
            self.out["peoplesoft_hints"].append({
                "path": rel, "line": 0,
                "hint": "PeopleSoft / PeopleTools path (filename or directory; not runtime proof)",
            })

    def _peoplesoft_text(self, rel, name, text):
        if name.lower() not in ("allowedhosts.properties", "configuration.properties", "psconfig.sh"):
            return
        if any(h["path"] == rel for h in self.out["peoplesoft_hints"]):
            return
        if re.search(r"(?i)people(?:soft|tools)|psigw|psemhub|PIA_HOME|PS_HOME", text):
            self.out["peoplesoft_hints"].append({
                "path": rel, "line": 0,
                "hint": "PeopleSoft / PeopleTools marker in config (file contents; not a live PIA probe)",
            })

    def _gmo_name(self, rel, name):
        lower = name.lower()
        if lower.endswith(".zone") or lower in GMO_DNS_NAMES:
            return

    def _gmo_text(self, rel, name, text):
        if not ONAMAE_HOST_RE.search(text):
            return
        lower = name.lower()
        dnsish = lower.endswith(".zone") or lower in GMO_DNS_NAMES or "dns" in rel.lower()
        if not (dnsish or ONAMAE_DNS_RE.search(text)):
            return
        if any(h["path"] == rel for h in self.out["gmo_onamae_hints"]):
            return
        self.out["gmo_onamae_hints"].append({
            "path": rel, "line": 0,
            "hint": "Onamae DNS or mail host in a local zone/config file (no live DNS query)",
        })

    def _mesh_vpn_name(self, rel, name):
        lower = name.lower()
        if lower in MESH_VPN_GENERIC_ACL_NAMES:
            return
        parts = {p.lower() for p in PurePosixPath(rel).parts}
        if parts & MESH_VPN_PATH_PARTS or lower in MESH_VPN_FILENAMES:
            self.out["mesh_vpn_hints"].append({
                "path": rel, "line": 0,
                "hint": "mesh VPN config or policy path (filename or directory; not runtime proof)",
            })

    def _mesh_vpn_text(self, rel, name, text):
        if not _looks_like_mesh_policy(text):
            return
        if any(h["path"] == rel and "ssh policy" in h["hint"] for h in self.out["mesh_vpn_hints"]):
            return
        self.out["mesh_vpn_hints"].append({
            "path": rel, "line": 0,
            "hint": "exported mesh / Tailscale-style ssh policy (file contents; confirm it is the live policy)",
        })

    def result(self, label, target):
        partial_reasons = sorted(self.gaps)
        if self.max_reached:
            partial_reasons.append("max_files_reached")
        out = {k: sorted(v, key=lambda e: (e.get("path", ""), e.get("line", 0), json.dumps(e, sort_keys=True)))
               for k, v in self.out.items()}
        dirs_with_lock = {(PurePosixPath(m["path"]).parent.as_posix(), m["ecosystem"]) for m in out["manifests"] if m["kind"] == "lockfile"}
        unlocked = sorted(m["path"] for m in out["manifests"]
                          if m["kind"] == "manifest" and (PurePosixPath(m["path"]).parent.as_posix(), m["ecosystem"]) not in dirs_with_lock)
        if partial_reasons:
            status = "PARTIAL"
        elif self.accepted_hits:
            status = "COMPLETE_WITH_ACCEPTED_EXCLUSIONS"
        else:
            status = "COMPLETE_FOR_LISTED_ROOT"
        doc = {
            "tool": "inventory.py", "version": VERSION, "label": label,
            "what_this_is": "Read-only file inventory. It is not a vulnerability scanner and proves nothing about deployed systems.",
            "limits": LIMITS,
            "coverage": {
                "status": status,
                "partial_reasons": partial_reasons,
                "files_seen": self.files_seen, "files_text_scanned": self.files_read,
                "gap_counts": dict(sorted(self.gaps.items())),
                "gaps": self.gap_paths,
                "accepted_exclusions": [{"pattern": p, "reason": why, "matched": self.accepted_hits.get(p, [])}
                                        for p, why in self.accepted],
                "note": "Symlinked, binary, special, oversized and excluded content is a coverage gap unless a human "
                        "accepted it with --accept-exclusion; accepted exclusions are still unscanned.",
            },
            "summary": {k: len(v) for k, v in sorted(out.items())},
            "nested_manifests": sorted(m["path"] for m in out["manifests"] if m["depth"] > 0),
            "unlocked_manifests": unlocked,
        }
        doc.update(out)
        if target:
            doc["inventory_manifests"] = [{"target": target, "path": m["path"], "scope_class": m["scope_class"]}
                                          for m in out["manifests"]]
        return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only local inventory (not a vulnerability scanner).")
    ap.add_argument("root")
    ap.add_argument("--out")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--target", help="target id to emit report-ready inventory_manifests")
    ap.add_argument("--label", help="label for the output (defaults to the root directory name)")
    ap.add_argument("--exclude-dir", action="append", default=None, help="directory name to skip (repeatable)")
    ap.add_argument("--max-files", type=int, default=50000)
    ap.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    ap.add_argument("--accept-exclusion", action="append", default=[], metavar="PATTERN=REASON",
                    help="human-accepted gap (symlink, binary, special, oversized or excluded path); recorded in output")
    ap.add_argument("--strict", action="store_true", help="exit 3 when coverage is PARTIAL")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("ERROR: %s is not a directory" % textscan.diagnostic_text(args.root), file=sys.stderr)
        return 2
    if args.target and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.target):
        print("ERROR: --target must be a report id", file=sys.stderr)
        return 2
    accepted = []
    for item in args.accept_exclusion:
        pattern, _sep, reason = item.partition("=")
        if not pattern.strip() or not reason.strip():
            print("ERROR: --accept-exclusion needs PATTERN=REASON with a non-empty reason", file=sys.stderr)
            return 2
        accepted.append((pattern.strip(), reason.strip()))
    excludes = DEFAULT_EXCLUDES if args.exclude_dir is None else args.exclude_dir
    inv = Inventory(root, excludes, args.max_files, args.max_file_bytes, accepted)
    try:
        inv.walk()
    except OSError as exc:  # includes safeio.Unsupported and refused symlinked roots
        print("ERROR: %s" % textscan.diagnostic_text(exc), file=sys.stderr)
        return 2
    doc = inv.result(args.label or os.path.basename(root), args.target)
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        try:
            safeio.safe_write(args.out, text, args.force)
        except OSError as exc:
            print("ERROR OUTPUT: %s" % textscan.diagnostic_text(exc), file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    status = doc["coverage"]["status"]
    print("inventory coverage: %s (%s)" % (status, ", ".join(doc["coverage"]["partial_reasons"]) or "no partial reasons"), file=sys.stderr)
    return 3 if (args.strict and status == "PARTIAL") else 0


if __name__ == "__main__":
    sys.exit(main())
