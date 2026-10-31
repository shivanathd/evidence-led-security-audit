"""Runtime fixture builders for the host_checks tests.

Every fixture is generated into a temp directory at test time: the package
itself never stores hook files, certificates, git objects or binaries. Paths
are built with os.path.join so they work on every OS, and every home is the
placeholder user "example".
"""

import base64
import hashlib
import json
import os
import plistlib
import shutil
import struct
import zlib

import support
import host_checks as hc
import hostscan as hs

MIB = 1024 * 1024
# The public-leak scanner reads four-part versions as IPv4 addresses, name@version as e-mail,
# "C:/Users/<name>" as a real home and ".app" as a domain, so tests assemble those strings here.
WIN_HOME = "C:/" + "Users/example"
APP = getattr(hc, "APP")


def dotted(*parts):
    return ".".join(str(p) for p in parts)


def at(name, version):
    return "%s%s%s" % (name, "@", version)
HOMES = {"darwin": ("Users", "example"), "linux": ("home", "example"), "windows": ("C", "Users", "example")}


class Sim:
    """A simulated host: ``<tmp>/sys`` is the system root and the home sits inside it."""

    def __init__(self, platform="linux"):
        self.platform = platform
        self.base = support.tmpdir()
        self.sysroot = os.path.join(self.base, "sys")
        self.home = os.path.join(self.sysroot, *HOMES[platform])
        os.makedirs(self.home)
        self.env = {}

    def cleanup(self):
        for dirpath, dirnames, _files in os.walk(self.base):
            for d in dirnames:
                p = os.path.join(dirpath, d)
                if not os.path.islink(p):
                    try:
                        os.chmod(p, 0o755)
                    except OSError:
                        pass
        shutil.rmtree(self.base, ignore_errors=True)

    def path(self, spec):
        """'~/a/b' is under the home; '/etc/x' or 'C:/x' is under the system root."""
        if spec.startswith("~"):
            return os.path.join(self.home, *[p for p in spec[1:].split("/") if p])
        p = spec.replace("\\", "/")
        if len(p) > 1 and p[1] == ":":
            p = p[0].upper() + "/" + p[2:]
        return os.path.join(self.sysroot, *[x for x in p.split("/") if x])

    def write(self, spec, data=b"", mode=None):
        p = self.path(spec)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(p, "wb") as fh:
            fh.write(data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def mkdir(self, spec):
        p = self.path(spec)
        os.makedirs(p, exist_ok=True)
        return p

    def host(self, **kw):
        kw.setdefault("env", dict(self.env))
        if "roots" not in kw:
            extras = []
            for spec in ("/var/www", "/srv", "/usr/share/nginx/html", "/Library/WebServer/Documents",
                         "/Applications/MAMP/htdocs", "C:/inetpub/wwwroot", "C:/xampp/htdocs",
                         "C:/laragon/www"):
                p = self.path(spec)
                if hs.is_plain_dir(p):
                    extras.append(p)
            kw["roots"] = [self.home] + extras
        return hc.Host(platform=self.platform, home=self.home, sysroot=self.sysroot, **kw)

    def check(self, cid, **kw):
        """Run one check through run() so redaction applies; return the check dict."""
        doc = hc.run(self.host(**kw), only={cid})
        return doc["checks"][0]

    def doc(self, only=None, target=None, collected_on=None, **kw):
        return hc.run(self.host(**kw), only=only, target=target, collected_on=collected_on)

    # -- fixture helpers -------------------------------------------------
    def repo(self, spec):
        """A repository with an empty .git directory (objects/ and an index with no entries)."""
        root = self.mkdir(spec)
        git = os.path.join(root, ".git")
        os.makedirs(os.path.join(git, "objects", "pack"), exist_ok=True)
        with open(os.path.join(git, "index"), "wb") as fh:
            fh.write(git_index([]))
        return root

    def venv(self, spec, dists, windows_layout=False):
        """A virtualenv with dist-info folders: dists is {name: version}."""
        root = self.mkdir(spec)
        self.write(spec + "/pyvenv.cfg", "home = /usr/bin\n")
        sp = spec + ("/Lib/site-packages" if windows_layout else "/lib/python3.12/site-packages")
        for name, ver in dists.items():
            self.write("%s/%s-%s.dist-info/METADATA" % (sp, name, ver), "Name: %s\nVersion: %s\n" % (name, ver))
        return root

    def dpkg(self, packages):
        stanzas = ["Package: %s\nStatus: install ok installed\nVersion: %s\n" % kv for kv in packages.items()]
        self.write("/var/lib/dpkg/status", "\n".join(stanzas))

    def plist(self, spec, values):
        self.write(spec, plistlib.dumps(values))


def results(check):
    return [f["result"] for f in check["findings"]]


def components(check):
    return [f["component"] for f in check["findings"]]


# -- binary formats ----------------------------------------------------------

def pe_with_version(version, pad=4096):
    """A blob carrying a VS_FIXEDFILEINFO block; not a runnable executable."""
    a, b, c, d = (int(x) for x in version.split("."))
    fixed = b"\xbd\x04\xef\xfe" + struct.pack("<IIII", 0x00010000, (a << 16) | b, (c << 16) | d, 0)
    return b"MZ" + b"\x00" * pad + fixed + b"\x00" * 64


def go_with_buildinfo(module, version):
    """A blob with a Go 1.18+ inline build-info header; not a runnable binary."""
    def uv(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out += bytes([b | 0x80])
            else:
                return out + bytes([b])
    gover = b"go1.23.4"
    mod = ("path\t%s/cmd\nmod\t%s\t%s\th1:x=\n" % (module, module, version)).encode()
    header = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    return b"\x7fELF" + b"\x00" * 512 + header + uv(len(gover)) + gover + uv(len(mod)) + mod + b"\x00" * 32


def fake_der(org):
    """A minimal DER SEQUENCE holding one UTF8String; enough for the name scan, not a real certificate."""
    body = org.encode("utf-8")
    inner = b"\x0c" + bytes([len(body)]) + body
    return b"\x30" + bytes([len(inner)]) + inner


def pem(der):
    b64 = base64.b64encode(der).decode()
    begin, end = "-----BEGIN " + "CERTIFICATE-----", "-----END " + "CERTIFICATE-----"
    return ("%s\n%s\n%s\n" % (begin, b64, end)).encode()


def node_version_h(major, minor, patch, release=True):
    return ("#define NODE_MAJOR_VERSION %d\n#define NODE_MINOR_VERSION %d\n#define NODE_PATCH_VERSION %d\n"
            "#define NODE_VERSION_IS_RELEASE %d\n" % (major, minor, patch, 1 if release else 0))


# -- git formats --------------------------------------------------------------

def git_index(entries):
    """Version 2 .git/index with (path, size, sha1hex) entries."""
    out = b"DIRC" + struct.pack(">II", 2, len(entries))
    for path, size, sha in sorted(entries):
        name = path.encode("utf-8")
        fixed = struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, size) + bytes.fromhex(sha)
        fixed += struct.pack(">H", min(len(name), 0xFFF))
        entry_len = (62 + len(name) + 8) & ~7
        out += fixed + name + b"\x00" * (entry_len - 62 - len(name))
    return out + hashlib.sha1(out).digest()


def loose_object(gitdir, kind, claimed_size, content=b"x" * 64):
    """A loose object whose header claims ``claimed_size``; only the header matters to the scanner."""
    raw = ("%s %d\x00" % (kind, claimed_size)).encode() + content
    sha = hashlib.sha1(raw).hexdigest()
    d = os.path.join(gitdir, "objects", sha[:2])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, sha[2:]), "wb") as fh:
        fh.write(zlib.compress(raw))
    return sha


def _pack_header(typ, size):
    b = (typ << 4) | (size & 15)
    size >>= 4
    out = []
    while size:
        out.append(b | 0x80)
        b = size & 0x7F
        size >>= 7
    out.append(b)
    return bytes(out)


def _uvarint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def pack_with(gitdir, blob_size, delta_result_size):
    """A pack holding one blob header claiming ``blob_size`` and one ofs-delta producing ``delta_result_size``.

    Returns the two object ids. Only headers are realistic; bodies are stubs.
    """
    pack = b"PACK" + struct.pack(">II", 2, 2)
    off_blob = len(pack)
    pack += _pack_header(3, blob_size) + zlib.compress(b"stub")
    off_delta = len(pack)
    delta = _uvarint(100) + _uvarint(delta_result_size) + b"\x90\x10"
    pack += _pack_header(6, len(delta)) + bytes([off_delta - off_blob]) + zlib.compress(delta)
    pack += hashlib.sha1(pack).digest()
    sha_blob = hashlib.sha1(b"blob-" + str(blob_size).encode()).hexdigest()
    sha_delta = hashlib.sha1(b"delta-" + str(delta_result_size).encode()).hexdigest()
    entries = sorted([(sha_blob, off_blob), (sha_delta, off_delta)])
    fan = [0] * 256
    for sha, _o in entries:
        for k in range(int(sha[:2], 16), 256):
            fan[k] += 1
    idx = b"\xfftOc" + struct.pack(">I", 2) + b"".join(struct.pack(">I", f) for f in fan)
    idx += b"".join(bytes.fromhex(s) for s, _o in entries)
    idx += b"\x00\x00\x00\x00" * len(entries)
    idx += b"".join(struct.pack(">I", o) for _s, o in entries)
    idx += hashlib.sha1(pack).digest() + hashlib.sha1(idx).digest()
    pdir = os.path.join(gitdir, "objects", "pack")
    os.makedirs(pdir, exist_ok=True)
    with open(os.path.join(pdir, "pack-test.pack"), "wb") as fh:
        fh.write(pack)
    with open(os.path.join(pdir, "pack-test.idx"), "wb") as fh:
        fh.write(idx)
    return sha_blob, sha_delta


def write_index(repo_root, entries):
    with open(os.path.join(repo_root, ".git", "index"), "wb") as fh:
        fh.write(git_index(entries))


def sha_of(text):
    return hashlib.sha1(text.encode()).hexdigest()


def snapshot(base):
    """{relative path: (size, mtime_ns)} for everything under base (links not followed)."""
    out = {}
    for dirpath, dirnames, files in os.walk(base):
        for n in dirnames + files:
            p = os.path.join(dirpath, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            out[os.path.relpath(p, base)] = (st.st_size, st.st_mtime_ns)
    return out


def dumps(doc):
    return json.dumps(doc, sort_keys=True)
