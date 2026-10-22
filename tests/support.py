"""Shared helpers for the stdlib-only test suite."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
EXAMPLES = ROOT / "assets" / "examples"
CORPUS = Path(__file__).resolve().parent / "corpus" / "adversarial_cases.json"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))

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
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return Path(dest)
