"""Read-only, cross-platform helpers for host_checks.py (standard library only).

Nothing here executes, imports, installs or writes anything. Files are read
only after an lstat shows a regular file, opened without following a final
symlink where the OS supports it, and re-checked by fstat so a FIFO or a
swapped path is never read. Every reader takes a byte limit. Directory walks
never follow symlinks or Windows reparse points, keep a visited set, and stop
at a depth, entry and time bound; each stop is recorded as a coverage gap.

Unlike safeio.py this module does not need openat, so it also runs on
Windows. The cost is weaker swap protection: a path component replaced by a
symlink between listing and reading can still be followed on hosts without
O_NOFOLLOW semantics for directories. host_checks.py reports that limit.
"""

import base64
import binascii
import fnmatch
import json
import os
import plistlib
import re
import stat
import struct
import time
import zlib

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

_VER = re.compile(r"^\s*(?:\d+:)?[vV]?(\d+(?:\.\d+)*)(.*)$", re.DOTALL)
_PRE = re.compile(r"(?i)^(?:[-._~+]?)(?:a|alpha|b|beta|c|rc|pre|preview|dev|nightly|canary|snapshot|next|insiders?|"
                  r"unstable|test|ea)(?:[-._]?\d+)*(?:[-._+].*)?$")
_PRE_ANY = re.compile(r"(?i)(?:^|[-._~+\d])(?:alpha|beta|rc|pre|preview|dev|nightly|canary|snapshot|next|unstable)"
                      r"(?:[-._]?\d+)*(?=$|[-._+])|^[-.]?(?:a|b|c)\d+(?=$|[-._+])")
_DISTRO = re.compile(r"(?i)(?:^-\d|ubuntu|deb\d|dfsg|\+b\d|el\d|fc\d|\.amzn|-r\d+$|alpine|\+esm|~)")
# Vendor build hashes such as Plex's "1.43.3.10861-a0bfb8370" are build metadata, not prereleases.
_BUILD_HASH = re.compile(r"(?i)^[-+][0-9a-f]{7,40}$")


class Version:
    """A loosely parsed version: numeric tuple plus anything after it."""

    __slots__ = ("raw", "nums", "rest", "prerelease", "vendor_suffix")

    def __init__(self, raw, nums, rest):
        self.raw = raw
        self.nums = nums
        self.rest = rest
        self.prerelease = bool(rest) and not _BUILD_HASH.match(rest) and bool(_PRE.match(rest) or _PRE_ANY.search(rest))
        self.vendor_suffix = bool(rest) and not self.prerelease and bool(_DISTRO.search(rest))

    def __repr__(self):
        return "Version(%r)" % self.raw


def parse_version(raw):
    """Return a Version or None. Accepts 'v24.22.1-nightly', '1:8.2.7-1ubuntu1', '1.2.0.post1'."""
    if raw is None:
        return None
    s = str(raw).strip().strip("\"'")
    m = _VER.match(s)
    if not m:
        return None
    try:
        nums = tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None
    if len(nums) > 8 or any(n > 10 ** 9 for n in nums):
        return None
    return Version(s, nums, m.group(2).strip())


def cmp_nums(a, b):
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return (a > b) - (a < b)


def at_least(version, fixed):
    """True when ``version`` is at or above ``fixed``. A prerelease of the fixed build is not fixed."""
    f = parse_version(fixed) if isinstance(fixed, str) else fixed
    c = cmp_nums(version.nums, f.nums)
    if c > 0:
        return True
    if c < 0:
        return False
    return not version.prerelease


def below(version, fixed):
    return not at_least(version, fixed)


def classify_lines(version, fixed_builds, line_len=1, no_fix_lines=()):
    """Classify against per-line fixed builds.

    Returns (result, note): result is 'ok', 'affected' or 'review'.
    ``no_fix_lines`` are line tuples the source says get no fix.
    """
    key = version.nums[:line_len]
    for fixed in fixed_builds:
        f = parse_version(fixed)
        if f.nums[:line_len] == key:
            if at_least(version, f):
                return "ok", "at or above fixed build %s" % fixed
            note = "below fixed build %s" % fixed
            if version.prerelease and cmp_nums(version.nums, f.nums) == 0:
                note = "prerelease of the fixed build %s is not treated as fixed" % fixed
            if version.vendor_suffix:
                note += "; distribution build string, confirm any vendor backport in its changelog"
            return "affected", note
    if key in {tuple(x) for x in no_fix_lines}:
        return "affected", "line %s gets no fix per the source" % ".".join(str(n) for n in key)
    return "review", "release line %s is not covered by the source's fixed builds" % ".".join(str(n) for n in key)


# --------------------------------------------------------------------------
# Safe reading
# --------------------------------------------------------------------------

class Gaps:
    """Coverage gaps: counts per kind plus a bounded list of examples."""

    def __init__(self, display, max_examples=200):
        self.display = display
        self.counts = {}
        self.examples = []
        self.max_examples = max_examples

    def add(self, kind, path=None, detail=None):
        self.counts[kind] = self.counts.get(kind, 0) + 1
        if len(self.examples) < self.max_examples:
            item = {"kind": kind}
            if path is not None:
                item["path"] = self.display(path)
            if detail:
                item["detail"] = detail
            self.examples.append(item)


def is_reparse(st):
    return bool(getattr(st, "st_file_attributes", 0) & REPARSE)


def lstat(path):
    try:
        return os.lstat(path)
    except (OSError, ValueError):
        return None


def is_regular(path):
    st = lstat(path)
    return st is not None and stat.S_ISREG(st.st_mode) and not is_reparse(st)


def is_plain_dir(path):
    st = lstat(path)
    return st is not None and stat.S_ISDIR(st.st_mode) and not is_reparse(st)


def exists_nofollow(path):
    return lstat(path) is not None


def read_bytes(path, limit, gaps=None, tail=False):
    """Return up to ``limit`` bytes of a regular file, or None.

    Returns None (and records a gap) for symlinks, non-regular files,
    unreadable files and files larger than ``limit`` unless ``tail`` asks for
    the last ``limit`` bytes instead.
    """
    st = lstat(path)
    if st is None:
        return None
    if stat.S_ISLNK(st.st_mode) or is_reparse(st):
        if gaps:
            gaps.add("symlink_not_followed", path)
        return None
    if not stat.S_ISREG(st.st_mode):
        if gaps:
            gaps.add("special_file", path)
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        if gaps:
            gaps.add("permission_denied", path)
        return None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (st.st_ino and fst.st_ino and fst.st_ino != st.st_ino):
            if gaps:
                gaps.add("changed_during_read", path)
            return None
        if fst.st_size > limit:
            if not tail:
                if gaps:
                    gaps.add("oversized", path)
                return None
            os.lseek(fd, fst.st_size - limit, os.SEEK_SET)
        chunks, left = [], limit
        while left > 0:
            b = os.read(fd, min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks)
    except OSError:
        if gaps:
            gaps.add("read_error", path)
        return None
    finally:
        os.close(fd)


def read_text(path, limit=2 * 1024 * 1024, gaps=None):
    data = read_bytes(path, limit, gaps)
    if data is None:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def read_json(path, limit=4 * 1024 * 1024, gaps=None):
    text = read_text(path, limit, gaps)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        if gaps:
            gaps.add("unparsed", path)
        return None


def listdir(path, gaps=None):
    """Names in a real directory (never through a symlink), sorted; [] when absent."""
    if not is_plain_dir(path):
        return []
    try:
        return sorted(os.listdir(path))
    except OSError:
        if gaps:
            gaps.add("permission_denied", path)
        return []


def subdirs(path, gaps=None):
    return [n for n in listdir(path, gaps) if is_plain_dir(os.path.join(path, n))]


# --------------------------------------------------------------------------
# Bounded walk
# --------------------------------------------------------------------------

class Budget:
    def __init__(self, seconds, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + seconds
        self.exhausted = False

    def left(self):
        return self.deadline - self.clock()

    def over(self):
        if not self.exhausted and self.clock() > self.deadline:
            self.exhausted = True
        return self.exhausted


class Walker:
    """Iterative, no-follow directory walk with depth, entry and time bounds.

    ``visit_dir(path, parts, names, ctx)`` is called once per directory with
    its entry names and the parent context; it returns (descend, child_ctx).
    ``visit_file(path, parts, name, st, ctx)`` is called per regular file.
    ``skip(parts, name_lower, child_ctx)`` prunes a child directory silently (by policy).
    """

    def __init__(self, gaps, budget, max_depth, max_entries, skip, visit_dir, visit_file):
        self.gaps = gaps
        self.budget = budget
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.skip = skip
        self.visit_dir = visit_dir
        self.visit_file = visit_file
        self.entries = 0
        self.dirs = 0
        self.stopped = None
        self._seen = set()

    def run(self, root, ctx=None):
        st = lstat(root)
        if st is None:
            return
        if stat.S_ISLNK(st.st_mode) or is_reparse(st):
            self.gaps.add("symlink_not_followed", root, "walk root is a link")
            return
        if not stat.S_ISDIR(st.st_mode):
            return
        stack = [(root, (), ctx)]
        while stack:
            if self.stopped:
                return
            path, parts, pctx = stack.pop()
            if self.budget.over():
                self.stopped = "time_budget"
                self.gaps.add("time_budget", path, "walk stopped; remaining directories not listed")
                return
            try:
                dst = os.lstat(path)
            except OSError:
                self.gaps.add("permission_denied", path)
                continue
            key = (dst.st_dev, dst.st_ino)
            if dst.st_ino:
                if key in self._seen:
                    self.gaps.add("loop_or_hardlink", path)
                    continue
                self._seen.add(key)
            try:
                with os.scandir(path) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError:
                self.gaps.add("permission_denied", path)
                continue
            self.dirs += 1
            names = [e.name for e in entries]
            descend, cctx = self.visit_dir(path, parts, names, pctx)
            if not descend:
                continue
            children = []
            for e in entries:
                self.entries += 1
                if self.entries > self.max_entries:
                    self.stopped = "max_entries"
                    self.gaps.add("max_entries", path, "entry bound reached; walk stopped")
                    return
                try:
                    est = e.stat(follow_symlinks=False)
                except OSError:
                    self.gaps.add("permission_denied", e.path)
                    continue
                if stat.S_ISLNK(est.st_mode) or is_reparse(est):
                    continue
                if stat.S_ISDIR(est.st_mode):
                    low = e.name.lower()
                    if self.skip(parts, low, cctx):
                        continue
                    if len(parts) + 1 > self.max_depth:
                        self.gaps.add("max_depth", e.path)
                        continue
                    children.append((e.path, parts + (e.name,), cctx))
                elif stat.S_ISREG(est.st_mode):
                    self.visit_file(e.path, parts, e.name, est, cctx)
            stack.extend(reversed(children))


# --------------------------------------------------------------------------
# Package metadata parsers
# --------------------------------------------------------------------------

def norm_py(name):
    return re.sub(r"[-_.]+", "_", name).lower()


_DIST = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-]*?)(?:-py[\d.]+)?(?:-[^-]+)?\.(?P<kind>dist-info|egg-info)$", re.I)


def python_dists(site_dir, wanted, gaps=None):
    """Yield (normalized_name, version, metadata_path) for wanted dists in a site-packages dir."""
    out = []
    for name in listdir(site_dir, gaps):
        m = _DIST.match(name)
        if not m:
            continue
        n = norm_py(m.group("name"))
        if n not in wanted:
            continue
        ver = m.group("ver")
        meta = os.path.join(site_dir, name, "METADATA" if name.lower().endswith("dist-info") else "PKG-INFO")
        text = read_text(meta, 512 * 1024) if is_regular(meta) else None
        if text:
            mv = re.search(r"(?m)^Version:\s*(\S+)", text)
            if mv:
                ver = mv.group(1)
        out.append((n, ver, os.path.join(site_dir, name)))
    return out


def vendored_certifi(site_dir):
    """Version of pip's vendored certifi, if present."""
    p = os.path.join(site_dir, "pip", "_vendor", "certifi", "__init__.py")
    text = read_text(p, 64 * 1024) if is_regular(p) else None
    if not text:
        return None
    m = re.search(r"""__version__\s*=\s*["']([^"']+)["']""", text)
    return (m.group(1), p) if m else None


def conda_meta(conda_meta_dir, wanted):
    out = []
    for name in listdir(conda_meta_dir):
        if not name.endswith(".json"):
            continue
        m = re.match(r"^(.+)-([^-]+)-([^-]+)\.json$", name)
        if m and norm_py(m.group(1)) in wanted:
            out.append((norm_py(m.group(1)), m.group(2), os.path.join(conda_meta_dir, name)))
    return out


def npm_lock_versions(text, kind, wanted):
    """Return {name: set(versions)} for wanted npm package names in a lockfile's text."""
    found = {}

    def add(name, ver):
        name = name.lower()
        if name in wanted:
            found.setdefault(name, set()).add(ver or "unknown")

    if kind in ("package-lock.json", "npm-shrinkwrap.json", ".package-lock.json"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            for key, val in (doc.get("packages") or {}).items():
                if not isinstance(val, dict):
                    continue
                name = val.get("name") or key.rsplit("node_modules/", 1)[-1]
                if "node_modules/" in key or val.get("name"):
                    add(name, str(val.get("version", "")))

            def legacy(deps):
                for name, val in (deps or {}).items():
                    if isinstance(val, dict):
                        add(name, str(val.get("version", "")))
                        legacy(val.get("dependencies"))
            legacy(doc.get("dependencies"))
            return found
    if kind == "yarn.lock":
        block = None
        for line in text.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                block = []
                for spec in line.rstrip(":").split(","):
                    spec = spec.strip().strip('"')
                    m = re.match(r"^(@?[^@\s]+)@", spec)
                    if m:
                        block.append(m.group(1))
                continue
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and block:
                for n in block:
                    add(n, m.group(1))
                block = None
        return found
    if kind == "pnpm-lock.yaml":
        for m in re.finditer(r"(?m)^\s{0,4}['\"]?/?(@?[^@\s'\"/:]+(?:/[^@\s'\"/:]+)?)[@/](\d[^\s:'\"()_]*)", text):
            add(m.group(1), m.group(2))
        return found
    if kind == "bun.lock":
        for m in re.finditer(r'"(@?[^"@\s]+(?:/[^"@\s]+)?)@(\d[^"\s]*)"', text):
            add(m.group(1), m.group(2))
        return found
    if kind == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return found
        if isinstance(doc, dict):
            for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                deps = doc.get(sect)
                if isinstance(deps, dict):
                    for name, spec in deps.items():
                        add(name, "spec:" + str(spec))
    return found


def py_pins(text, kind, wanted):
    """Return {name: set(version_or_spec)} for wanted Python packages in a manifest or lockfile."""
    found = {}

    def add(name, ver):
        n = norm_py(name)
        if n in wanted:
            found.setdefault(n, set()).add(ver)

    if kind in ("poetry.lock", "uv.lock", "pdm.lock", "pylock.toml"):
        for m in re.finditer(r'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
            add(m.group(1), m.group(2))
        return found
    if kind == "Pipfile.lock":
        try:
            doc = json.loads(text)
        except ValueError:
            return found
        for sect in ("default", "develop"):
            for name, val in (doc.get(sect) or {}).items() if isinstance(doc, dict) else ():
                if isinstance(val, dict) and isinstance(val.get("version"), str):
                    add(name, val["version"].lstrip("="))
        return found
    # Drop #-comments so "# litellm==1.107.0" is not treated as a pin.
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    for m in re.finditer(r"(?im)(?<![^\s\"',\[])([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?"
                         r"\s*([0-9][0-9A-Za-z.+!*-]*)?", text):
        name, op, ver = m.group(1), m.group(3), m.group(4)
        if norm_py(name) not in wanted:
            continue
        if op in ("==", "===") and ver:
            add(name, ver)
        elif op or ver:
            add(name, "spec:%s%s" % (op or "", ver or ""))
        else:
            add(name, "spec:unpinned")
    return found


def cargo_lock_versions(text, wanted):
    found = {}
    for m in re.finditer(r'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        if m.group(1).lower() in wanted:
            found.setdefault(m.group(1).lower(), set()).add(m.group(2))
    return found


# --------------------------------------------------------------------------
# Binary metadata (no execution)
# --------------------------------------------------------------------------

def pe_file_version(path, limit=16 * 1024 * 1024):
    """FileVersion from a Windows PE VS_FIXEDFILEINFO block, scanning the head and tail of the file."""
    # read_bytes(tail=False) returns None for oversized files. The version
    # resource often sits in the head, so the head pass uses _read_head.
    for data in (read_bytes(path, limit, tail=True), _read_head(path, limit)):
        if not data:
            continue
        i = data.find(b"\xbd\x04\xef\xfe")
        while i != -1 and i + 16 <= len(data):
            _sig, _struc, ms, ls = struct.unpack_from("<IIII", data, i)
            ver = "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
            if ms:
                return ver
            i = data.find(b"\xbd\x04\xef\xfe", i + 4)
    return None


def _uvarint(buf, pos):
    shift = result = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            break
    return None, pos


def go_main_module(path, limit=256 * 1024 * 1024):
    """(module_path, version) from a Go binary's embedded build info (Go 1.18+ inline format), or None."""
    st = lstat(path)
    if st is None or not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    data = read_bytes(path, limit)
    if not data:
        return None
    i = data.find(b"\xff Go buildinf:")
    if i == -1 or i + 32 > len(data):
        return None
    flags = data[i + 15]
    if not flags & 0x2:
        return None
    pos = i + 32
    _gover_len, pos = _uvarint(data, pos)
    if _gover_len is None:
        return None
    pos += _gover_len
    mod_len, pos = _uvarint(data, pos)
    if mod_len is None or mod_len > 1 << 20:
        return None
    mod = data[pos:pos + mod_len].decode("utf-8", "replace")
    m = re.search(r"(?m)^mod\t(\S+)\t(\S+)", mod)
    return (m.group(1), m.group(2)) if m else None


def plist_value(path, key):
    data = read_bytes(path, 4 * 1024 * 1024)
    if not data:
        return None
    try:
        doc = plistlib.loads(data)
    except Exception:  # plistlib raises several types on malformed input
        return None
    val = doc.get(key) if isinstance(doc, dict) else None
    return str(val) if val is not None else None


def ini_value(text, key):
    m = re.search(r"(?mi)^\s*%s\s*=\s*(\S+)" % re.escape(key), text or "")
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------

_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")


def pem_certificates(data):
    for m in _PEM.finditer(data or b""):
        try:
            yield base64.b64decode(b"".join(m.group(1).split()), validate=True)
        except (binascii.Error, ValueError):
            continue


_DER_STRINGS = {0x0C, 0x13, 0x14, 0x16, 0x1E}


def der_mentions(der, needle=b"emudhra"):
    """Return the first DER string value (UTF8/Printable/IA5/BMP) that contains ``needle``, or None.

    Falls back to the printable run around the match when no string element wraps it.
    """
    low = der.lower()
    i = low.find(needle)
    if i == -1:
        i = low.find(needle.decode("ascii").encode("utf-16-be"))
        if i == -1:
            return None
    for start in range(i - 2, max(-1, i - 131), -1):
        tag = der[start]
        if tag not in _DER_STRINGS or start + 2 > len(der):
            continue
        length, head = der[start + 1], 2
        if length & 0x80:
            if length != 0x81 or start + 3 > len(der):
                continue
            length, head = der[start + 2], 3
        body = der[start + head:start + head + length]
        if len(body) != length or not (start + head <= i < start + head + length):
            continue
        text = body.decode("utf-16-be", "replace") if tag == 0x1E else body.decode("utf-8", "replace")
        if needle.decode() in text.lower():
            return text
    lo = i
    while lo > 0 and 32 <= der[lo - 1] < 127 and i - lo < 64:
        lo -= 1
    hi = i
    while hi < len(der) and 32 <= der[hi] < 127 and hi - i < 64:
        hi += 1
    return der[lo:hi].decode("ascii", "replace")


# --------------------------------------------------------------------------
# Git object store (parsed directly; git is never run)
# --------------------------------------------------------------------------

def git_index_entries(gitdir, limit=64 * 1024 * 1024):
    """Return {path: (size, sha1hex)} from .git/index (versions 2-4), or None if unreadable."""
    data = read_bytes(os.path.join(gitdir, "index"), limit)
    if not data or data[:4] != b"DIRC":
        return None if data is None else {}
    try:
        return _parse_git_index(data)
    except (ValueError, struct.error, IndexError):
        return None


def _parse_git_index(data):
    version, count = struct.unpack_from(">II", data, 4)
    if version not in (2, 3, 4):
        return None
    pos, out, prev = 12, {}, b""
    for _ in range(count):
        if pos + 62 > len(data):
            break
        size = struct.unpack_from(">I", data, pos + 36)[0]
        sha = data[pos + 40:pos + 60].hex()
        flags = struct.unpack_from(">H", data, pos + 60)[0]
        p = pos + 62
        if version >= 3 and flags & 0x4000:
            p += 2
        if version == 4:
            strip, p = _uvarint(data, p)
            end = data.index(b"\x00", p)
            name = prev[:len(prev) - (strip or 0)] + data[p:end]
            p = end + 1
            pos = p
        else:
            end = data.index(b"\x00", p)
            name = data[p:end]
            entry_len = (end - pos + 8) & ~7
            pos += entry_len
        prev = name
        out[name.decode("utf-8", "replace")] = (size, sha)
    return out


def _delta_result_size(raw):
    try:
        d = zlib.decompressobj().decompress(raw, 64)
    except zlib.error:
        return None
    _base, p = _uvarint(d, 0)
    if _base is None:
        return None
    size, _ = _uvarint(d, p)
    return size


def git_large_blobs(gitdir, lo, hi, budget, max_objects=5_000_000, gaps=None):
    """Yield (sha1hex, size, where) for blobs whose size is within [lo, hi].

    Reads loose object headers and pack index/entry headers only. Deltified
    entries report their reconstructed size. Stops when ``budget`` runs out.
    """
    objdir = os.path.join(gitdir, "objects")
    results, seen = [], 0
    for sub in listdir(objdir, gaps):
        if len(sub) != 2:
            continue
        for name in listdir(os.path.join(objdir, sub)):
            seen += 1
            if seen > max_objects or budget.over():
                return results, False
            p = os.path.join(objdir, sub, name)
            st = lstat(p)
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            head = _read_head(p, 256)
            if not head:
                continue
            try:
                hdr = zlib.decompressobj().decompress(head, 64)
            except zlib.error:
                continue
            m = re.match(rb"(blob|tree|commit|tag) (\d+)\x00", hdr)
            if m and m.group(1) == b"blob" and lo <= int(m.group(2)) <= hi:
                results.append((sub + name, int(m.group(2)), "loose"))
    packdir = os.path.join(objdir, "pack")
    for name in listdir(packdir, gaps):
        if not name.endswith(".idx"):
            continue
        idx = read_bytes(os.path.join(packdir, name), 512 * 1024 * 1024, gaps)
        pack = os.path.join(packdir, name[:-4] + ".pack")
        if not idx or idx[:4] != b"\xfftOc" or not is_regular(pack):
            if gaps:
                gaps.add("unparsed", os.path.join(packdir, name), "pack index not version 2")
            continue
        try:
            offsets = _pack_offsets(idx)
        except (struct.error, IndexError):
            if gaps:
                gaps.add("unparsed", os.path.join(packdir, name), "pack index truncated")
            continue
        offsets.sort()
        pack_size = lstat(pack).st_size
        try:
            fd = os.open(pack, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            if gaps:
                gaps.add("permission_denied", pack)
            continue
        try:
            for k, (off, sha) in enumerate(offsets):
                seen += 1
                if seen > max_objects or budget.over():
                    return results, False
                nxt = offsets[k + 1][0] if k + 1 < len(offsets) else pack_size - 20
                if nxt - off < 0:
                    continue
                os.lseek(fd, off, os.SEEK_SET)
                buf = os.read(fd, 64)
                if not buf:
                    continue
                b = buf[0]
                typ, size, shift, p = (b >> 4) & 7, b & 15, 4, 1
                while b & 0x80 and p < len(buf):
                    b = buf[p]
                    p += 1
                    size |= (b & 0x7F) << shift
                    shift += 7
                if typ == 3:
                    if lo <= size <= hi:
                        results.append((sha, size, "pack"))
                    continue
                if typ not in (6, 7):
                    continue
                # Only a delta that could produce a large result needs its header inflated.
                if typ == 6:
                    while p < len(buf) and buf[p] & 0x80:
                        p += 1
                    p += 1
                else:
                    p += 20
                os.lseek(fd, off + p, os.SEEK_SET)
                rsize = _delta_result_size(os.read(fd, 256))
                if rsize is not None and lo <= rsize <= hi:
                    results.append((sha, rsize, "pack-delta (blob or other object)"))
        finally:
            os.close(fd)
    return results, True


def _pack_offsets(idx):
    n = struct.unpack_from(">I", idx, 8 + 255 * 4)[0]
    names_at, offs_at = 8 + 256 * 4, 8 + 256 * 4 + n * 20 + n * 4
    large_at = offs_at + n * 4
    offsets = []
    for k in range(n):
        off = struct.unpack_from(">I", idx, offs_at + k * 4)[0]
        if off & 0x80000000:
            off = struct.unpack_from(">Q", idx, large_at + (off & 0x7FFFFFFF) * 8)[0]
        offsets.append((off, idx[names_at + k * 20:names_at + k * 20 + 20].hex()))
    return offsets


def _read_head(path, n):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, n)
    finally:
        os.close(fd)


def lfs_patterns(gitattributes_text):
    pats = []
    for line in (gitattributes_text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and any(p in ("filter=lfs",) for p in parts[1:]):
            pats.append(parts[0])
    return pats


def lfs_match(rel_path, patterns):
    rel = rel_path.replace("\\", "/")
    base = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        pat = pat.lstrip("/")
        if "/" in pat:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.rstrip("/") + "/**"):
                return True
        elif fnmatch.fnmatch(base, pat):
            return True
    return False


# --------------------------------------------------------------------------
# Small TOML subset (tables and string values), enough for agent configs
# --------------------------------------------------------------------------

def toml_tables(text):
    """Return {table_path: {key: raw_value}} for a TOML document; values stay raw strings."""
    tables, cur = {"": {}}, ""
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$", line)
        if m:
            cur = ".".join(p.strip().strip("\"'") for p in re.findall(r'"[^"]*"|\'[^\']*\'|[^.]+', m.group(1)))
            tables.setdefault(cur, {})
            continue
        m = re.match(r'^("[^"]*"|\'[^\']*\'|[A-Za-z0-9_.-]+)\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = m.group(1).strip("\"'"), m.group(2)
        depth = val.count("[") + val.count("{") - val.count("]") - val.count("}")
        while depth > 0 and i < len(lines):
            nxt = lines[i]
            i += 1
            val += "\n" + nxt
            depth += nxt.count("[") + nxt.count("{") - nxt.count("]") - nxt.count("}")
        if val.startswith(('"""', "'''")):
            q = val[:3]
            while val.count(q) < 2 and i < len(lines):
                val += "\n" + lines[i]
                i += 1
        if "." in key:
            sub, key = key.rsplit(".", 1)
            tables.setdefault((cur + "." if cur else "") + sub, {})[key] = val
        else:
            tables[cur][key] = val
    return tables


def toml_strings(raw):
    return [a or b for a, b in re.findall(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'', raw or "")]
