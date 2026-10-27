"""Shared helpers for the stdlib-only test suite."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# SKILL.md name must match this directory name. The workspace checkout
# may be named something else; copies used by the package checker use this.
SKILL_DIR_NAME = "evidence-led-security-audit"
SCRIPTS = ROOT / "scripts"
EXAMPLES = ROOT / "assets" / "examples"
CORPUS = Path(__file__).resolve().parent / "corpus" / "adversarial_cases.json"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))

import safeio  # noqa: E402 - needs the scripts folder on sys.path

# inventory.py, check_public_package.py and render_report --out exit BLOCKED without
# POSIX openat support (Windows); host_checks.py and validate_report.py still run there.
POSIX_ONLY = unittest.skipIf(safeio.HOST_SUPPORT_ERROR, "needs POSIX openat support; the script exits BLOCKED here")

# Built at runtime so the package never stores secret-shaped strings.
PLACEHOLDERS = {
    "{{FAKE_AWS_KEY}}": "AKIA" + "Z" * 16,
    "{{FAKE_GH_TOKEN}}": "ghp_" + "a1" * 18,
}


def load_example(kind):
    name = "baseline-report.json" if kind == "baseline" else "after-fix-report.json"
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def expand(value):
    if isinstance(value, str):
        for k, v in PLACEHOLDERS.items():
            value = value.replace(k, v)
        return value
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    return value


_SEG = re.compile(r"^([A-Za-z_]+)(?:\[(id=[^\]]+|\d+)\])?$")


def _step(node, seg):
    m = _SEG.match(seg)
    if not m:
        raise ValueError("bad path segment %s" % seg)
    key, sel = m.group(1), m.group(2)
    node = node[key]
    if sel is None:
        return node
    if sel.startswith("id="):
        want = sel[3:]
        for item in node:
            if item.get("id") == want:
                return item
        raise KeyError(want)
    return node[int(sel)]


def apply_ops(doc, ops):
    doc = copy.deepcopy(doc)
    for op in ops:
        segs = op["path"].split(".")
        parent = doc
        for seg in segs[:-1]:
            parent = _step(parent, seg)
        last = segs[-1]
        m = _SEG.match(last)
        key, sel = m.group(1), m.group(2)
        if op["op"] == "set":
            parent[key] = expand(op["value"])
        elif op["op"] == "append":
            parent[key].append(expand(op["value"]))
        elif op["op"] == "delete":
            if sel is None:
                del parent[key]
            else:
                parent[key].remove(_step(parent, last))
        else:
            raise ValueError(op["op"])
    return doc


def tmpdir():
    """A new temp directory as a canonical path.

    The scripts refuse any path with a symlinked component. On macOS the default
    temp root (/var/folders/...) sits under the /var -> /private/var symlink, so
    tests must resolve it first.
    """
    return os.path.realpath(tempfile.mkdtemp())


def run_script(name, *args, cwd=None):
    cmd = [sys.executable, "-B", str(SCRIPTS / name)] + [str(a) for a in args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)


def clean_copy(dest):
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    return Path(dest)


def package_copy():
    """Copy the skill tree into a directory whose name matches SKILL.md."""
    return clean_copy(Path(tmpdir()) / SKILL_DIR_NAME)
