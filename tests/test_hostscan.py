import os
import plistlib
import shutil
import struct
import unittest

import support
import hostfix
import hostscan as hs

MIB = hostfix.MIB
CAN_SYMLINK = hasattr(os, "symlink")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class Versions(unittest.TestCase):
    def test_weird_strings_parse(self):
        cases = {
            "v24.22.1-nightly": ((24, 22, 1), True),
            "24.22.1-pre": ((24, 22, 1), True),
            "10.0.14-preview.1": ((10, 0, 14), True),
            "1.2.0rc1": ((1, 2, 0), True),
            "1.2.0.post1": ((1, 2, 0), False),
            "1:8.4.27-1ubuntu1": ((8, 4, 27), False),
            " 'v1.2.3' ": ((1, 2, 3), False),
            "1.43.3.10861-a0bfb8370": ((1, 43, 3, 10861), False),
        }
        for raw, (nums, pre) in cases.items():
            v = hs.parse_version(raw)
            self.assertEqual((v.nums, v.prerelease), (nums, pre), raw)

    def test_unparseable(self):
        for raw in (None, "", "latest", "lts-alpine", "x1.2", "1." + "9" * 12):
            self.assertIsNone(hs.parse_version(raw), raw)

    def test_distro_suffix_marked(self):
        self.assertTrue(hs.parse_version("8.4.26-1ubuntu1").vendor_suffix)
        self.assertTrue(hs.parse_version("22.23.3-1nodesource1").vendor_suffix)

    def test_prerelease_of_fixed_build_is_not_fixed(self):
        self.assertFalse(hs.at_least(hs.parse_version("24.22.1-nightly"), "24.22.1"))
        self.assertTrue(hs.at_least(hs.parse_version("24.22.1"), "24.22.1"))
        self.assertTrue(hs.at_least(hs.parse_version("24.22.2-nightly"), "24.22.1"))
        self.assertTrue(hs.at_least(hs.parse_version(hostfix.dotted(1, 2, 1, 0)), "1.2.1"))

    def test_classify_lines(self):
        fixed = ["22.23.4", "24.22.1", "26.12.1"]
        self.assertEqual(hs.classify_lines(hs.parse_version("22.23.3"), fixed, 1, [(20,)])[0], "affected")
        self.assertEqual(hs.classify_lines(hs.parse_version("24.22.1"), fixed, 1, [(20,)])[0], "ok")
        self.assertEqual(hs.classify_lines(hs.parse_version("20.19.5"), fixed, 1, [(20,)])[0], "affected")
        self.assertEqual(hs.classify_lines(hs.parse_version("23.11.0"), fixed, 1, [(20,)])[0], "review")
        res, note = hs.classify_lines(hs.parse_version("22.23.3-1nodesource1"), fixed, 1)
        self.assertEqual(res, "affected")
        self.assertIn("backport", note)
        php = ["8.5.12", "8.4.27", "8.3.36", "8.2.35"]
        self.assertEqual(hs.classify_lines(hs.parse_version("8.4.30"), php, 2)[0], "ok")
        self.assertEqual(hs.classify_lines(hs.parse_version("8.1.30"), php, 2)[0], "review")
        self.assertEqual(hs.classify_lines(hs.parse_version("1.43.2.9999"), ["1.43.3.10861"], 0)[0], "affected")


class SafeReading(unittest.TestCase):
    def setUp(self):
        self.d = support.tmpdir()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.gaps = hs.Gaps(lambda p: p)

    def test_limits_and_tail(self):
        p = os.path.join(self.d, "f.bin")
        with open(p, "wb") as fh:
            fh.write(b"a" * 100 + b"END")
        self.assertIsNone(hs.read_bytes(p, 10, self.gaps))
        self.assertEqual(self.gaps.counts.get("oversized"), 1)
        self.assertEqual(hs.read_bytes(p, 3, tail=True), b"END")
        self.assertIsNone(hs.read_text(p + ".missing"))

    def test_binary_is_not_text_and_bad_json_is_a_gap(self):
        p = os.path.join(self.d, "b")
        with open(p, "wb") as fh:
            fh.write(b"\x00\x01{")
        self.assertIsNone(hs.read_text(p))
        q = os.path.join(self.d, "j.json")
        with open(q, "w") as fh:
            fh.write("{not json")
        self.assertIsNone(hs.read_json(q, gaps=self.gaps))
        self.assertIn("unparsed", self.gaps.counts)

    @unittest.skipUnless(CAN_SYMLINK and os.name != "nt", "symlinks need POSIX here")
    def test_symlink_never_read(self):
        target = os.path.join(self.d, "secret")
        with open(target, "w") as fh:
            fh.write("value")
        link = os.path.join(self.d, "link")
        os.symlink(target, link)
        self.assertIsNone(hs.read_bytes(link, 100, self.gaps))
        self.assertIn("symlink_not_followed", self.gaps.counts)
        self.assertEqual(hs.listdir(link), [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_fifo_not_opened(self):
        p = os.path.join(self.d, "pipe")
        os.mkfifo(p)
        self.assertIsNone(hs.read_bytes(p, 100, self.gaps))
        self.assertIn("special_file", self.gaps.counts)

    def test_unicode_and_spaces(self):
        d = os.path.join(self.d, "My Repo \u00fc\u4e2d")
        os.makedirs(d)
        with open(os.path.join(d, "f i\u00e9.txt"), "w", encoding="utf-8") as fh:
            fh.write("ok")
        self.assertEqual(hs.listdir(d), ["f i\u00e9.txt"])
        self.assertEqual(hs.read_text(os.path.join(d, "f i\u00e9.txt")), "ok")


class Walking(unittest.TestCase):
    def setUp(self):
        self.d = support.tmpdir()
        self.addCleanup(self._cleanup)
        self.gaps = hs.Gaps(lambda p: p)

    def _cleanup(self):
        for dirpath, dirnames, _ in os.walk(self.d):
            for n in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, n), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.d, True)

    def walk(self, root, **kw):
        files = []
        w = hs.Walker(self.gaps, hs.Budget(kw.get("seconds", 30)), kw.get("depth", 10), kw.get("entries", 10000),
                      lambda parts, low, ctx: low == "node_modules",
                      lambda path, parts, names, ctx: (True, ctx),
                      lambda path, parts, name, st, ctx: files.append("/".join(parts + (name,))))
        w.run(root)
        return w, files

    def make(self, *rel):
        p = os.path.join(self.d, *rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write("x")

    def test_skip_depth_and_entries(self):
        self.make("a", "b", "c", "deep.txt")
        self.make("node_modules", "pkg", "index.js")
        self.make("top.txt")
        w, files = self.walk(self.d)
        self.assertIn("a/b/c/deep.txt", files)
        self.assertFalse(any(f.startswith("node_modules") for f in files))
        w, files = self.walk(self.d, depth=1)
        self.assertNotIn("a/b/c/deep.txt", files)
        self.assertIn("max_depth", self.gaps.counts)
        w, _ = self.walk(self.d, entries=1)
        self.assertEqual(w.stopped, "max_entries")
        w, _ = self.walk(self.d, seconds=-1)
        self.assertEqual(w.stopped, "time_budget")

    @unittest.skipUnless(CAN_SYMLINK and os.name != "nt", "symlinks need POSIX here")
    def test_symlink_loop_terminates(self):
        self.make("a", "f.txt")
        os.symlink(self.d, os.path.join(self.d, "a", "loop"))
        os.symlink(os.path.join(self.d, "a", "loop2"), os.path.join(self.d, "a", "loop2"))
        w, files = self.walk(self.d)
        self.assertEqual(files, ["a/f.txt"])
        self.assertIsNone(w.stopped)

    @unittest.skipIf(os.name == "nt" or IS_ROOT, "chmod 000 does not block root or Windows")
    def test_unreadable_dir_is_a_gap(self):
        self.make("locked", "f.txt")
        self.make("open", "g.txt")
        os.chmod(os.path.join(self.d, "locked"), 0)
        w, files = self.walk(self.d)
        self.assertEqual(files, ["open/g.txt"])
        self.assertIn("permission_denied", self.gaps.counts)


class Parsers(unittest.TestCase):
    def setUp(self):
        self.d = support.tmpdir()
        self.addCleanup(shutil.rmtree, self.d, True)

    def put(self, rel, data):
        p = os.path.join(self.d, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data.encode() if isinstance(data, str) else data)
        return p

    def test_python_dists_and_vendored_certifi(self):
        self.put("sp/LiteLLM-1.107.0.dist-info/METADATA", "Version: 1.107.0\n")
        self.put("sp/brotli-1.2.0-py3.12.egg-info/PKG-INFO", "Version: 1.2.0\n")
        self.put("sp/requests-2.0.dist-info/METADATA", "Version: 2.0\n")
        self.put("sp/pip/_vendor/certifi/__init__.py", '__version__ = "2023.07.22"\n')
        found = {n: v for n, v, _p in hs.python_dists(os.path.join(self.d, "sp"), {"litellm", "brotli"})}
        self.assertEqual(found, {"litellm": "1.107.0", "brotli": "1.2.0"})
        self.assertEqual(hs.vendored_certifi(os.path.join(self.d, "sp"))[0], "2023.07.22")

    def test_conda_meta(self):
        self.put("cm/certifi-2025.1.31-pyhd8ed1ab_0.json", "{}")
        self.assertEqual(hs.conda_meta(os.path.join(self.d, "cm"), {"certifi"})[0][:2], ("certifi", "2025.1.31"))

    def test_npm_lock_formats(self):
        lock = '{"packages": {"": {"name": "app"}, "node_modules/testmetest": {"version": "1.0.3"},' \
               ' "node_modules/a/node_modules/function-color": {"version": "2.0.0"}}}'
        self.assertEqual(hs.npm_lock_versions(lock, "package-lock.json", {"testmetest", "function-color"}),
                         {"testmetest": {"1.0.3"}, "function-color": {"2.0.0"}})
        yarn = '"testmetest@^1.0.0", testmetest@1:\n  version "1.0.3"\n'
        self.assertEqual(hs.npm_lock_versions(yarn, "yarn.lock", {"testmetest"}), {"testmetest": {"1.0.3"}})
        pnpm = "packages:\n  /%s:\n    resolution: {}\n  '%s':\n" % (hostfix.at("testmetest", "1.0.3"), hostfix.at("@vitest/ui", "5.0.1"))
        self.assertEqual(hs.npm_lock_versions(pnpm, "pnpm-lock.yaml", {"testmetest", "@vitest/ui"}),
                         {"testmetest": {"1.0.3"}, "@vitest/ui": {"5.0.1"}})
        self.assertEqual(hs.npm_lock_versions('{"devDependencies": {"testmetest": "^1"}}', "package.json",
                                              {"testmetest"}), {"testmetest": {"spec:^1"}})
        self.assertEqual(hs.npm_lock_versions("{broken", "package-lock.json", {"x"}), {})

    def test_py_pins(self):
        text = "LiteLLM[proxy]==1.107.0\nbrotli>=1.1\ncertifi\n# litellm==9\n"
        found = hs.py_pins(text, "requirements.txt", {"litellm", "brotli", "certifi"})
        self.assertEqual(found["litellm"], {"1.107.0"})
        self.assertEqual(found["brotli"], {"spec:>=1.1"})
        self.assertEqual(found["certifi"], {"spec:unpinned"})
        lock = '[[package]]\nname = "litellm"\nversion = "1.106.2"\n'
        self.assertEqual(hs.py_pins(lock, "uv.lock", {"litellm"}), {"litellm": {"1.106.2"}})
        self.assertEqual(hs.py_pins("# litellm==1.107.0\nRUN pip install litellm==1.106.2\n",
                                   "dockerfile", {"litellm"}), {"litellm": {"1.106.2"}})
        self.assertEqual(hs.cargo_lock_versions('[[package]]\nname = "wasmtime"\nversion = "48.0.6"\n', {"wasmtime"}),
                         {"wasmtime": {"48.0.6"}})

    def test_pe_and_go_and_plist(self):
        self.assertEqual(hs.pe_file_version(self.put("a.dll", hostfix.pe_with_version(hostfix.dotted(8, 4, 27, 0)))), hostfix.dotted(8, 4, 27, 0))
        self.assertIsNone(hs.pe_file_version(self.put("b.dll", b"MZ" + b"\x00" * 100)))
        # Version in the head of a file larger than the scan window: tail-only would miss it.
        head_only = hostfix.pe_with_version(hostfix.dotted(8, 4, 27, 0), pad=48)
        self.assertGreater(len(head_only), 80)
        self.assertEqual(hs.pe_file_version(self.put("head.dll", head_only), limit=80), hostfix.dotted(8, 4, 27, 0))
        self.assertEqual(hs.go_main_module(self.put("ovh", hostfix.go_with_buildinfo("github.com/ovh/ovhcloud-cli", "v0.13.0"))),
                         ("github.com/ovh/ovhcloud-cli", "v0.13.0"))
        self.assertIsNone(hs.go_main_module(self.put("plain", b"\x7fELF" + b"\x00" * 100)))
        p = self.put("Info.plist", plistlib.dumps({"CFBundleShortVersionString": "156.0.7000.1"}))
        self.assertEqual(hs.plist_value(p, "CFBundleShortVersionString"), "156.0.7000.1")
        self.assertIsNone(hs.plist_value(self.put("bad.plist", b"garbage"), "x"))
        self.assertEqual(hs.ini_value("[App]\nVersion=140.0\n", "Version"), "140.0")

    def test_der_mentions_and_pem(self):
        der = hostfix.fake_der("eMudhra Example CA")
        certs = list(hs.pem_certificates(hostfix.pem(der) + b"junk" + hostfix.pem(hostfix.fake_der("Other CA"))))
        self.assertEqual(len(certs), 2)
        self.assertEqual(hs.der_mentions(certs[0]), "eMudhra Example CA")
        self.assertIsNone(hs.der_mentions(certs[1]))
        bmp = "eMudhra BMP".encode("utf-16-be")
        self.assertEqual(hs.der_mentions(b"\x30\x20\x1e" + bytes([len(bmp)]) + bmp), "eMudhra BMP")

    def test_git_index_and_objects(self):
        gitdir = os.path.join(self.d, ".git")
        os.makedirs(os.path.join(gitdir, "objects"))
        sha = hostfix.sha_of("a")
        with open(os.path.join(gitdir, "index"), "wb") as fh:
            fh.write(hostfix.git_index([("dir/big file \u00fc.bin", 13 * MIB, sha), ("small.txt", 10, sha)]))
        self.assertEqual(hs.git_index_entries(gitdir)["dir/big file \u00fc.bin"], (13 * MIB, sha))
        loose = hostfix.loose_object(gitdir, "blob", 13 * MIB)
        hostfix.loose_object(gitdir, "commit", 13 * MIB)
        b, d = hostfix.pack_with(gitdir, 13 * MIB, 12 * MIB)
        res, complete = hs.git_large_blobs(gitdir, 11 * MIB, 16 * MIB, hs.Budget(30))
        self.assertTrue(complete)
        self.assertEqual(sorted((s, w.split(" ")[0]) for s, _z, w in res),
                         sorted([(loose, "loose"), (b, "pack"), (d, "pack-delta")]))
        res, complete = hs.git_large_blobs(gitdir, 11 * MIB, 16 * MIB, hs.Budget(-1))
        self.assertFalse(complete)

    def test_truncated_git_files_are_gaps_not_crashes(self):
        gitdir = os.path.join(self.d, ".git")
        os.makedirs(os.path.join(gitdir, "objects", "pack"))
        with open(os.path.join(gitdir, "index"), "wb") as fh:
            fh.write(b"DIRC" + struct.pack(">II", 2, 5) + b"\x00" * 70)
        self.assertIsInstance(hs.git_index_entries(gitdir), (dict, type(None)))
        with open(os.path.join(gitdir, "index"), "wb") as fh:
            fh.write(b"DIRC\x00")
        self.assertIsNone(hs.git_index_entries(gitdir))
        for n, data in (("pack-x.idx", b"\xfftOc" + struct.pack(">I", 2) + b"\xff" * 1100),
                        ("pack-x.pack", b"PACK")):
            with open(os.path.join(gitdir, "objects", "pack", n), "wb") as fh:
                fh.write(data)
        gaps = hs.Gaps(lambda p: p)
        res, complete = hs.git_large_blobs(gitdir, 1, 2, hs.Budget(30), gaps=gaps)
        self.assertEqual(res, [])
        self.assertIn("unparsed", gaps.counts)

    def test_lfs(self):
        pats = hs.lfs_patterns("*.bin filter=lfs diff=lfs merge=lfs -text\nassets/** filter=lfs\n*.md text\n")
        self.assertTrue(hs.lfs_match("models/w.bin", pats))
        self.assertTrue(hs.lfs_match("assets/v/clip.mp4", pats))
        self.assertFalse(hs.lfs_match("payload.dat", pats))

    def test_toml(self):
        text = '[mcp_servers.docs]\ncommand = "npx"\nargs = [\n  "-y",\n  "docs-mcp"\n]\n' \
               '[mcp_servers.docs.env]\nTOKEN = "x"\n[model_providers.p]\nbase_url = "https://llm.example.net/v1"\n'
        t = hs.toml_tables(text)
        self.assertEqual(hs.toml_strings(t["mcp_servers.docs"]["args"]), ["-y", "docs-mcp"])
        self.assertIn("TOKEN", t["mcp_servers.docs.env"])
        self.assertEqual(hs.toml_strings(t["model_providers.p"]["base_url"]), ["https://llm.example.net/v1"])


if __name__ == "__main__":
    unittest.main()
