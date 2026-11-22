"""Fixture tests for the 22 Nov 2026 Bitwarden CLI CVE-2026-42994 watch.

Synthetic hosts only. Nothing here executes bw, bun, gh, node or any audited
program. No malware bytes, no credential values, no network, no exfil URLs.
"""

import hashlib
import json
import os
import unittest
from unittest import mock

import hostfix
import host_checks as hc

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

results = hostfix.results
at = hostfix.at
dotted = hostfix.dotted
CID = "bitwarden-cli-42994"
# Assembled at runtime so the public-leak scanner does not read a version as an email or IPv4.
PNPM_MAL = at("@bitwarden+cli", "2026.4.0")
PNPM_FLOOR = at("@bitwarden+cli", "2026.4.1")
EXFIL_IP = dotted(94, 154, 172, 43)
EXFIL_HOST = "checkmarx" + "." + "cx"


class SimCase(unittest.TestCase):
    platform = "linux"

    def setUp(self):
        self.s = self.sim(self.platform)

    def sim(self, platform):
        s = hostfix.Sim(platform)
        self.addCleanup(s.cleanup)
        return s

    def assertStatus(self, check, status):
        self.assertEqual(check["status"], status, json.dumps(check, indent=1)[:3000])

    def check(self, **kw):
        return self.s.check(CID, **kw)

    def lock(self, version, rel="~/code/app/package-lock.json"):
        self.s.write(rel, json.dumps({
            "packages": {
                "node_modules/@bitwarden/cli": {
                    "name": "@bitwarden/cli",
                    "version": version,
                }
            }
        }))

    def pkg_json(self, spec, rel="~/code/app/package.json"):
        self.s.write(rel, json.dumps({"dependencies": {"@bitwarden/cli": spec}}))


class Catalog(SimCase):
    def test_new_id_and_count(self):
        self.assertEqual(len(hc.CHECK_IDS), 81)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        self.assertIn(CID, hc.CHECK_IDS)
        self.assertIn(CID, hc.INDICATOR_CHECKS)
        meta = next(m for m in hc.CHECKS if m["id"] == CID)
        self.assertTrue(meta["uses_walk"])
        self.assertTrue(meta["sources"])
        for key in meta["sources"]:
            self.assertIn(key, hc.SRC)
            self.assertTrue(hc.SRC[key][1].startswith("https://"), key)
        self.assertNotIn(EXFIL_HOST, json.dumps(hc.SRC).lower())
        self.assertNotIn(EXFIL_IP, json.dumps(hc.SRC))

    def test_skipped_rows_name_non_host_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("GitHub Action", blob)
        self.assertIn("snap", blob.lower())
        self.assertIn("Runner.Worker", blob)
        self.assertIn("locale", blob.lower())


class EmptyAndExact(SimCase):
    def test_empty_is_pass(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check(CID), "PASS")

    def test_lock_2026_4_0_is_affected(self):
        self.lock("2026.4.0")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("2026.4.0", json.dumps(c))

    def test_lock_2026_4_1_is_info(self):
        self.lock("2026.4.1")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_lock_2026_3_0_is_info(self):
        self.lock("2026.3.0")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_lock_2026_11_0_is_info(self):
        self.lock("2026.11.0")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_lock_missing_version_is_unknown(self):
        self.s.write("~/code/app/package-lock.json", json.dumps({
            "packages": {
                "node_modules/@bitwarden/cli": {"name": "@bitwarden/cli"}
            }
        }))
        c = self.check()
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_package_json_exact_pin_is_affected(self):
        self.pkg_json("2026.4.0")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])


class Ranges(SimCase):
    def test_caret_2026_3_0_is_review(self):
        self.pkg_json("^2026.3.0")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_tilde_2026_3_0_cannot_include_malicious(self):
        self.pkg_json("~2026.3.0")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_caret_2026_4_0_is_review(self):
        self.pkg_json("^2026.4.0")
        self.assertEqual(results(self.check()), ["review"])

    def test_caret_2026_4_1_is_info(self):
        self.pkg_json("^2026.4.1")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_compound_or_range_is_review(self):
        self.pkg_json("^2026.4.1 || 2026.4.0")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_tilde_major_only_is_review(self):
        self.pkg_json("~2026")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_unpinned_latest_is_review(self):
        self.pkg_json("latest")
        self.assertEqual(results(self.check()), ["review"])

    def test_star_is_review(self):
        self.pkg_json("*")
        self.assertEqual(results(self.check()), ["review"])

    def test_gte_floor_is_info(self):
        self.pkg_json(">=2026.4.1")
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])


class ScopedInstall(SimCase):
    def test_node_modules_scoped_2026_4_0(self):
        self.s.write("~/code/app/node_modules/@bitwarden/cli/package.json",
                     json.dumps({"name": "@bitwarden/cli", "version": "2026.4.0"}))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_node_modules_scoped_2026_4_1(self):
        self.s.write("~/code/app/node_modules/@bitwarden/cli/package.json",
                     json.dumps({"name": "@bitwarden/cli", "version": "2026.4.1"}))
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_global_prefix_scoped(self):
        self.s.write("/usr/local/lib/node_modules/@bitwarden/cli/package.json",
                     json.dumps({"name": "@bitwarden/cli", "version": "2026.4.0"}))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_hidden_package_lock_nested(self):
        self.s.write("~/code/app/node_modules/.package-lock.json", json.dumps({
            "packages": {
                "node_modules/@bitwarden/cli": {"name": "@bitwarden/cli", "version": "2026.4.0"}
            }
        }))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))

    def test_pnpm_virtual_store_scoped_plus(self):
        self.s.mkdir("~/code/app/node_modules/.pnpm/" + PNPM_MAL)
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        blob = json.dumps(c)
        self.assertNotIn("@bitwarden/cli-2026.4.0", blob)

    def test_pnpm_virtual_store_floor_is_info(self):
        self.s.mkdir("~/code/app/node_modules/.pnpm/" + PNPM_FLOOR)
        c = self.check()
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_npm_cache_uses_unscoped_tarball_name(self):
        needle = "@bitwarden/cli/-/cli-2026.4.0.tgz"
        self.s.write("~/.npm/_cacache/index-v5/ab/cd/idx",
                     json.dumps({"key": "make-fetch-happen:request-cache:/" + needle}))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        blob = json.dumps(c)
        self.assertNotIn("@bitwarden/cli-2026.4.0.tgz", blob)

    def test_unrelated_cli_tarball_is_not_a_hit(self):
        self.s.write("~/.npm/_cacache/index-v5/ab/cd/idx",
                     b"other-cli/-/cli-2026.4.0.tgz\n")
        self.assertStatus(self.check(), "PASS")

    @unittest.skipIf(os.name == "nt" or IS_ROOT, "chmod 000 does not block root or Windows")
    def test_unreadable_npm_cache_index_records_gap(self):
        path = self.s.write("~/.npm/_cacache/index-v5/ab/cd/idx", b"not-the-needle\n")
        os.chmod(path, 0)
        self.addCleanup(lambda: os.chmod(path, 0o644))
        doc = self.s.doc(only={CID})
        self.assertStatus(doc["checks"][0], "PASS")
        self.assertIn("permission_denied", doc["coverage"]["partial_reasons"])


class Iocs(SimCase):
    def test_named_loader_wrong_hash_is_review(self):
        self.s.write("~/code/app/bw_setup.js", b"innocuous loader stand-in\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_named_payload_wrong_hash_is_review(self):
        self.s.write("~/code/app/bw1.js", b"innocuous payload stand-in\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_payload_over_one_mib_is_hashed_not_unknown(self):
        # Larger than the previous 1 MiB hash cap; under the 16 MiB bound.
        self.s.write("~/code/app/bw1.js", b"x" * (2 * hc.MIB))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        self.assertNotIn("unknown", results(c))

    def test_matching_loader_hash_is_affected(self):
        path = self.s.write("~/code/app/bw_setup.js", b"innocuous loader stand-in\n")

        def fake_sha(p, limit=64 * hc.MIB):
            if os.path.normcase(os.path.abspath(p)) == os.path.normcase(os.path.abspath(path)):
                return hc.BW_LOADER_SHA
            return hashlib.sha256(b"x").hexdigest()

        with mock.patch.object(hc, "sha256_of", side_effect=fake_sha):
            c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_upgraded_package_with_leftover_loader_is_fail(self):
        self.lock("2026.4.1")
        self.s.write("~/code/app/node_modules/@bitwarden/cli/bw_setup.js", b"leftover\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertIn("review", results(c))
        self.assertIn("info", results(c))

    def test_lock_file_path_is_review(self):
        self.s.write("/tmp/tmp.987654321.lock", b"12345\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_staging_tarball_is_review(self):
        self.s.write("/tmp/package-updated.tgz", b"not a real tarball\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_staging_dir_is_review(self):
        self.s.mkdir("/tmp/_tmp_")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_rc_butlerian_needle(self):
        self.s.write("~/.bashrc", "echo Would be executing butlerian jihad!\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_rc_heredoc_token(self):
        self.s.write("~/.zshrc", "echo << 'EOF'\nnot a manifesto\nEOF\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))

    def test_ordinary_bitwarden_mention_is_not_a_hit(self):
        self.s.write("~/.bashrc", "alias bwhelp='bitwarden vault help'\n")
        self.s.write("~/notes/dune.md", "The fremen wait for Shai-Hulud in the book.\n")
        self.assertStatus(self.check(), "PASS")

    def test_dune_repo_name_is_review(self):
        self.s.repo("~/sandworm-fremen-042")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_git_description_string_is_review(self):
        root = self.s.repo("~/code/notes")
        with open(os.path.join(root, ".git", "description"), "w", encoding="utf-8") as fh:
            fh.write("Shai-Hulud: The Third Coming\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_output_has_no_exfil_host(self):
        self.lock("2026.4.0")
        blob = json.dumps(self.check()).lower()
        self.assertNotIn(EXFIL_HOST, blob)
        self.assertNotIn(EXFIL_IP, blob)
        self.assertNotIn("audit.checkmarx", blob)


class DarwinTemp(SimCase):
    platform = "darwin"

    def test_private_tmp_lock_is_review(self):
        self.s.write("/private/tmp/tmp.987654321.lock", b"12345\n")
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])


class WindowsScoped(SimCase):
    platform = "windows"

    def test_scoped_node_modules_join(self):
        self.s.write("~/code/app/node_modules/@bitwarden/cli/package.json",
                     json.dumps({"name": "@bitwarden/cli", "version": "2026.4.0"}))
        c = self.check()
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
