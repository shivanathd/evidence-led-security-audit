#!/usr/bin/env python3
"""Pre-publication check for a skill package or report bundle.

Looks for things that should not ship publicly: secret-shaped values, hosts
outside reserved example domains and a reviewed allowlist of references,
emails, non-documentation IP addresses, account-like IDs, local home paths,
caller-supplied private terms, symlinks, install or shell hooks, caches and
archives. Matched secret values and denylist terms are never printed.

A clean result means no listed rule matched. It does not prove the package
is free of private information; a human reviewer still signs off.

Usage:
  python3 scripts/check_public_package.py DIR [--denylist FILE]
                                          [--host-policy FILE] [--json]
The denylist is a local, unshipped text file with one private term per line
(people, organizations, internal hostnames, repository names).
Exit codes: 0 no rule matched, 1 errors found, 2 usage error or unsupported host,
3 needs human review (unscanned binary content). Host overrides are echoed.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safeio  # noqa: E402
import textscan  # noqa: E402

DEFAULT_ALLOWED_HOSTS = textscan.REVIEWED_PUBLIC_HOSTS
REQUIRED_FILES = ["SKILL.md", "LICENSE", "README.md", "SECURITY.md"]
FORBIDDEN = ["__pycache__", "*.pyc", ".DS_Store", "*.zip", "*.tar", "*.tar.gz", "*.tgz", ".env", ".env.*",
             "*.pem", "*.key", "*.p12", "node_modules", ".git", "*.log", "*.sqlite", "*.db"]
HOOK_FILES = {"setup.py": "setup.py runs code at install", ".pre-commit-config.yaml": "git hook configuration",
              "hooks.json": "agent hook configuration"}
LOCAL_PATH = re.compile(r"(/home/[a-z_][a-z0-9_-]*/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\)")
# Compact target includes CI config and dated incident profiles. Raise it
# when a new dated profile is justified. 100 remains the hard error.
MAX_FILES_ERROR, MAX_FILES_TARGET = 100, 50
HUB_CHAR_TARGET, DESCRIPTION_WORD_LIMIT = 4000, 50


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, code, path, msg):
        self.items.append({"level": level, "code": code,
                           "path": textscan.diagnostic_text(path),
                           "message": textscan.diagnostic_text(msg)})

    @property
    def errors(self):
        return [i for i in self.items if i["level"] == "ERROR"]


def _frontmatter(text):
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    return text[4:end] if end != -1 else None


def check_skill_md(root, text, rep):
    fm = _frontmatter(text)
    if fm is None:
        rep.add("ERROR", "SKILL_FRONTMATTER", "SKILL.md", "must start with YAML frontmatter")
        return
    name = re.search(r"^name:\s*(\S+)\s*$", fm, re.M)
    if not name or name.group(1).strip("'\"") != root.name:
        rep.add("ERROR", "SKILL_NAME", "SKILL.md", "name must match the directory name")
    desc = re.search(r"^description:\s*(.+)$", fm, re.M)
    if not desc:
        rep.add("ERROR", "SKILL_DESCRIPTION", "SKILL.md", "description is required")
    else:
        words = len(desc.group(1).strip().strip("'\"").split())
        if words >= DESCRIPTION_WORD_LIMIT:
            rep.add("WARNING", "SKILL_DESCRIPTION", "SKILL.md", "description has %d words; keep it under %d" % (words, DESCRIPTION_WORD_LIMIT))
    if len(text) > HUB_CHAR_TARGET:
        rep.add("WARNING", "HUB_SIZE", "SKILL.md", "%d characters; the compact-hub target is under %d" % (len(text), HUB_CHAR_TARGET))


def check_hooks(rel, name, text, rep):
    if name in HOOK_FILES:
        rep.add("ERROR", "INSTALL_HOOK", rel, HOOK_FILES[name])
    if name == "package.json":
        try:
            scripts = (json.loads(text) or {}).get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        for h in sorted(set(scripts) & {"preinstall", "install", "postinstall", "prepare"}):
            rep.add("ERROR", "INSTALL_HOOK", rel, "package.json %s script" % h)
    if name == "pyproject.toml" and re.search(r"^\[build-system\]", text, re.M):
        rep.add("ERROR", "INSTALL_HOOK", rel, "build-system section runs a build backend at install")
    if name.endswith(".json") and "/.claude/" in "/" + rel and '"hooks"' in text:
        rep.add("ERROR", "INSTALL_HOOK", rel, "agent settings with shell hooks")


def scan(root, denylist, allowed_hosts, max_bytes=2 * 1024 * 1024, host_records=()):
    root = Path(os.path.abspath(root))
    rep = Report()
    default = frozenset(DEFAULT_ALLOWED_HOSTS)
    allowed = frozenset(allowed_hosts) | {r["host"] for r in host_records}
    suppressed = 0
    seen = set()
    prune = lambda rel, name: any(fnmatch.fnmatchcase(name, p) for p in FORBIDDEN)  # noqa: E731
    entries = []
    for kind, rel, dfd, name, st in safeio.walk(str(root), prune):
        if kind == "dir":
            continue
        if kind == "excluded_dir":
            if rel == ".git":
                # The package's own repository: history ships with it but is not scanned here.
                rep.add("WARNING", "GIT_HISTORY", ".git/",
                        "history is not scanned by this check; scan it with a history-aware secret scanner "
                        "(for example gitleaks git) before publishing")
            else:
                rep.add("ERROR", "FORBIDDEN_ARTIFACT", rel + "/", "remove before packaging")
            continue
        if kind == "symlink":
            rep.add("ERROR", "SYMLINK", rel, "symlinks are not allowed in a public package")
            continue
        if kind != "file":
            rep.add("ERROR", "UNSCANNED", rel, "not scanned (%s); cannot be cleared" % kind)
            continue
        entries.append(rel)
        seen.add(rel)
        if any(fnmatch.fnmatchcase(name, p) for p in FORBIDDEN):
            rep.add("ERROR", "FORBIDDEN_ARTIFACT", rel, "remove before packaging")
            continue
        if st.st_mode & 0o111 and not rel.startswith("scripts/"):
            rep.add("WARNING", "EXECUTABLE_BIT", rel, "executable file outside scripts/")
        try:
            data = safeio.read_at(dfd, name, st, max_bytes)
        except safeio.SkipFile as exc:
            rep.add("ERROR", "UNSCANNED", rel, "not scanned (%s); cannot be cleared" % exc)
            continue
        if b"\x00" in data[:8192]:
            rep.add("REVIEW", "BINARY_NEEDS_REVIEW", rel, "binary file not scanned; a human must review or remove it")
            continue
        text = data.decode("utf-8", errors="replace")
        for pattern, start, _e in textscan.find_secrets(text):
            rep.add("ERROR", "SECRET", "%s:%d" % (rel, textscan.line_of(text, start)), "secret-shaped value (%s)" % pattern)
        hits = textscan.find_public_leaks(text, allowed, denylist)
        for kind_, start, _e, detail in hits:
            rep.add("ERROR", "PUBLIC_LEAK", "%s:%d" % (rel, textscan.line_of(text, start)), "%s: %s" % (kind_, detail))
        if host_records:
            suppressed += len(textscan.find_public_leaks(text, default, denylist)) - len(hits)
        for m in LOCAL_PATH.finditer(text):
            rep.add("ERROR", "LOCAL_PATH", "%s:%d" % (rel, textscan.line_of(text, m.start())), "local home path reveals a username")
        check_hooks(rel, name, text, rep)
        if rel == "SKILL.md":
            check_skill_md(root, text, rep)
    for req in REQUIRED_FILES:
        if req not in seen:
            rep.add("ERROR", "MISSING_FILE", req, "required for a public skill package")
    if len(entries) > MAX_FILES_ERROR:
        rep.add("ERROR", "FILE_COUNT", ".", "%d files; packages are limited to %d" % (len(entries), MAX_FILES_ERROR))
    elif len(entries) > MAX_FILES_TARGET:
        rep.add("WARNING", "FILE_COUNT", ".", "%d files; the compact target is %d or fewer" % (len(entries), MAX_FILES_TARGET))
    for rec in textscan.policy_summaries(host_records):
        rep.add("OVERRIDE", "HOST_OVERRIDE", rec["override_id"],
                "full policy remains local; human sign-off required")
    rep.suppressed = suppressed
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check a package for content unsafe to publish.")
    ap.add_argument("dir")
    ap.add_argument("--denylist", help="local file of private terms, one per line (never shipped)")
    ap.add_argument("--host-policy", help="reviewed JSON host-override policy with approver role and rationale")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.dir):
        print("ERROR: %s is not a directory" % textscan.diagnostic_text(args.dir), file=sys.stderr)
        return 2
    denylist, records = [], []
    try:
        if args.denylist:
            raw = safeio.read_file(args.denylist, 1024 * 1024).decode("utf-8")
            denylist = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
        if args.host_policy:
            root_resolved = os.path.realpath(args.dir)
            policy_resolved = os.path.realpath(args.host_policy)
            if os.path.commonpath([root_resolved, policy_resolved]) == root_resolved:
                raise ValueError("host policy must be supplied outside the package under review")
            _hosts, records = textscan.parse_host_policy(json.loads(safeio.read_file(args.host_policy, 256 * 1024).decode("utf-8")))
        rep = scan(args.dir, denylist, DEFAULT_ALLOWED_HOSTS, host_records=records)
        if records:
            rep.add("REVIEW", "HOST_POLICY_REQUIRES_SIGNOFF", ".",
                    "host overrides are asserted policy, not proof of human approval; obtain independent release sign-off")
    except safeio.SkipFile as exc:
        print("ERROR: cannot read input file (%s)" % textscan.diagnostic_text(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:  # includes safeio.Unsupported and rejected policies
        print("ERROR: %s" % textscan.diagnostic_text(exc), file=sys.stderr)
        return 2
    review = [i for i in rep.items if i["level"] == "REVIEW"]
    if rep.errors:
        status, code = "PACKAGE_BLOCKED", 1
    elif review:
        status, code = "NEEDS_REVIEW", 3
    else:
        status, code = "NO_RULE_MATCHED", 0
    if args.json:
        print(json.dumps({"status": status, "errors": len(rep.errors), "needs_review": len(review),
                          "host_overrides": textscan.policy_summaries(records),
                          "matches_allowed_by_overrides": rep.suppressed,
                          "items": rep.items}, indent=2, sort_keys=True))
    else:
        for i in rep.items:
            print("%s %s %s: %s" % (i["level"], i["code"], i["path"], i["message"]))
        if not args.denylist:
            print("NOTE: no --denylist given; private names and internal hosts specific to you were not checked.")
        if records:
            print("NOTE: %d match(es) were allowed by the reviewed host policy." % rep.suppressed)
        print("%s (%d error(s), %d needing review). Pattern checks only; a human still reviews before publishing."
              % (status, len(rep.errors), len(review)))
    return code


if __name__ == "__main__":
    sys.exit(main())
