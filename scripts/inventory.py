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
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safeio  # noqa: E402
import textscan  # noqa: E402

VERSION = "0.1.0"
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
    "bun.lockb": "npm", "composer.lock": "composer", "poetry.lock": "python", "Pipfile.lock": "python",
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
    r"base64 (?:-d|--decode)|auto-?approve|dangerously)")
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
            "fatal_error_backtraces", "max_input_nesting_level", "max_input_vars", "pm.max_requests",
            "expose_php", "display_errors", "pm.status_path", "ping.path"]
PHP_SETTING = re.compile(
    r"^\s*(?:php_(?:admin_)?(?:value|flag)\s*(?:\[\s*)?)?(%s)(?:\s*\])?\s*[=\s]\s*([^\s;#]+)"
    % "|".join(re.escape(k) for k in PHP_KEYS))
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.IGNORECASE)
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
NGINX_LISTEN = re.compile(r"^\s*listen\s+([^;]+);")
FPM_LISTEN = re.compile(r"^\s*listen\s*=\s*(\S+)")
APACHE_LISTEN = re.compile(r"^\s*Listen\s+(\S+)")
PHP_SAPI_PKG = re.compile(r"\b(php\d*(?:\.\d+)?-fpm|php\d*-fpm|libapache2-mod-php\S*|php\d*-cgi|lsphp\d*|frankenphp)\b", re.IGNORECASE)


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
        self.out = {k: [] for k in ("manifests", "containers", "listeners", "php_runtime_hints", "install_hooks",
                                    "ci_workflows", "agent_instruction_files", "secret_candidates",
                                    "sensitive_filenames", "sidecar_artifacts", "symlinks")}

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
        if name == "setup.py":
            self.out["install_hooks"].append({"path": rel, "hook": "setup.py (arbitrary code at install time)"})
        if name == ".pre-commit-config.yaml" or rel.startswith(".husky/"):
            self.out["install_hooks"].append({"path": rel, "hook": "developer git hook configuration"})
        if name == ".user.ini":
            self.out["php_runtime_hints"].append({"path": rel, "line": 0, "hint": ".user.ini present: applied after request startup, so it is not an early-config mitigation"})

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
        if name == "composer.json":
            self._json_hooks(rel, text, "scripts", COMPOSER_HOOKS)
            self._composer_php(rel, text)
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
                    if re.match(r"(?:[\w.-]+/)*php:", ref) or "frankenphp" in ref or "litespeed" in ref:
                        self.out["php_runtime_hints"].append({"path": rel, "line": i + 1, "hint": "PHP base image %s (tag is a hint, not runtime proof)" % ref})
                if m.group(2):
                    stages.add(m.group(2))
            m = EXPOSE_RE.match(ln)
            if m:
                for port in m.group(1).split():
                    expose.append(port)
                    self.out["listeners"].append({"path": rel, "line": i + 1, "source": "EXPOSE", "value": port})
            if re.match(r"^\s*USER\s+", ln, re.IGNORECASE):
                user = ln.split(None, 1)[1].strip() if len(ln.split(None, 1)) > 1 else ""
            for pm in PHP_SAPI_PKG.finditer(ln):
                self.out["php_runtime_hints"].append({"path": rel, "line": i + 1, "hint": "package or SAPI reference %s" % pm.group(1)})
        self.out["containers"].append({"path": rel, "from": froms, "expose": expose,
                                       "user": user if user is not None else "not set (defaults to image user, often root)"})

    def _compose(self, rel, lines):
        ports_indent = None
        for i, ln in enumerate(lines):
            if not ln.strip() or ln.strip().startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip())
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
        self.out["ci_workflows"].append({
            "path": rel, "unpinned_actions": unpinned,
            "pull_request_target": "pull_request_target" in text,
            "remote_script_piped_to_shell": bool(re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh", text)),
            "secrets_references": len(re.findall(r"\$\{\{\s*secrets\.", text)),
        })

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

    def _composer_php(self, rel, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        req = doc.get("require") if isinstance(doc, dict) else None
        if isinstance(req, dict) and isinstance(req.get("php"), str):
            self.out["php_runtime_hints"].append({"path": rel, "line": 0, "hint": "composer requires php %s (source constraint, not runtime proof)" % req["php"]})

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
