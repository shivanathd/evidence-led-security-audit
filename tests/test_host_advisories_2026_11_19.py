"""Fixture tests for the 19 Nov 2026 host-check watch.

Synthetic hosts only. Nothing here executes nginx, LiteLLM, python or any
audited program. No PoC payloads, no credential values, no network.
"""

import json
import unittest

import hostfix
import host_checks as hc

results = hostfix.results
dotted = hostfix.dotted


def _llm_from(tag, tab=False):
    img = "registry.example.com/berriai/litellm:" + tag
    return ("FROM\t" if tab else "FROM ") + img + "\n"


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


class Catalog(SimCase):
    def test_new_ids_and_count(self):
        self.assertEqual(len(hc.CHECK_IDS), 73)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        self.assertIn("litellm-40217", hc.CHECK_IDS)
        self.assertIn("nginx-123007", hc.CHECK_IDS)
        self.assertIn("axis-90436", hc.CHECK_IDS)
        self.assertIn("litellm-1-107-0", hc.CHECK_IDS)
        self.assertIn("nginx-present", hc.CHECK_IDS)
        self.assertNotIn("litellm-40217", hc.INDICATOR_CHECKS)
        self.assertNotIn("nginx-123007", hc.INDICATOR_CHECKS)
        for cid in ("litellm-40217", "nginx-123007"):
            meta = next(m for m in hc.CHECKS if m["id"] == cid)
            self.assertTrue(meta["uses_walk"], cid)
            self.assertTrue(meta["sources"], cid)

    def test_skipped_rows_name_non_host_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("CVE-2024-10441", blob)
        self.assertIn("CVE-2026-90817", blob)
        self.assertIn("BIG-IP", blob)
        self.assertIn("Oyster", blob)


class LiteLlm40217(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("litellm-40217"), "NOT_APPLICABLE")

    def test_range_start_is_affected(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.81.8"})
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_just_below_floor_is_affected(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.83.9"})
        self.assertEqual(results(self.s.check("litellm-40217")), ["affected"])

    def test_ghsa_floor_is_info(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.83.10"})
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_below_intro_is_info(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.81.7"})
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_prerelease_of_floor_is_affected(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.83.10rc1"})
        self.assertEqual(results(self.s.check("litellm-40217")), ["affected"])

    def test_malicious_1_107_0_is_info_for_this_cve(self):
        self.s.venv("~/venvs/llm", {"litellm": "1.107.0"})
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_exact_pin_below_floor(self):
        self.s.write("~/code/app/requirements.txt", "litellm==1.83.9\n")
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_exact_pin_at_floor(self):
        self.s.write("~/code/app/requirements.txt", "litellm==1.83.10\n")
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_arbitrary_equality_pin(self):
        self.s.write("~/code/app/requirements.txt", "litellm===1.83.9\n")
        self.assertEqual(results(self.s.check("litellm-40217")), ["affected"])

    def test_unpinned_spec_is_review(self):
        self.s.write("~/code/app/requirements.txt", "litellm>=1.80\n")
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_wildcard_pin_is_review(self):
        self.s.write("~/code/app/requirements.txt", "litellm==1.83.*\n")
        self.assertEqual(results(self.s.check("litellm-40217")), ["review"])

    def test_image_tag_in_range(self):
        self.s.write("~/code/app/Dockerfile", _llm_from("1.83.9"))
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_from_tab_is_an_image(self):
        self.s.write("~/code/app/Dockerfile", _llm_from("1.83.9", tab=True).rstrip("\n") + " AS proxy\n")
        self.assertEqual(results(self.s.check("litellm-40217")), ["affected"])

    def test_digest_pinned_is_unknown(self):
        digest = "a" * 64
        self.s.write("~/code/app/Dockerfile", _llm_from("1.83.10").rstrip("\n") + "@sha256:%s\n" % digest)
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertIn("digest-pinned", c["findings"][0]["detail"])

    def test_moving_tag_is_unknown(self):
        self.s.write("~/code/app/Dockerfile", _llm_from("latest"))
        c = self.s.check("litellm-40217")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_compose_environment_image_key_is_not_an_image(self):
        self.s.write("~/code/app/compose.yml",
                     "services:\n  api:\n    image: postgres:16\n    environment:\n"
                     "      image: %s" % _llm_from("1.83.9").replace("FROM ", ""))
        self.assertStatus(self.s.check("litellm-40217"), "NOT_APPLICABLE")

    def test_no_poc_or_master_key_in_helper(self):
        with open(hc.__file__, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("sk-litellm", text)
        self.assertNotIn("marshal.loads", text)


class Nginx123007(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("nginx-123007"), "NOT_APPLICABLE")

    def test_stable_below_floor(self):
        self.s.dpkg({"nginx": "1.30.6-1"})
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_stable_floor_is_info(self):
        self.s.dpkg({"nginx": "1.30.7-1"})
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_mainline_below_floor(self):
        self.s.dpkg({"nginx": "1.31.8-1"})
        self.assertEqual(results(self.s.check("nginx-123007")), ["affected"])

    def test_mainline_floor_is_info(self):
        self.s.dpkg({"nginx": "1.31.9-1"})
        self.assertEqual(results(self.s.check("nginx-123007")), ["info"])

    def test_newer_train_is_info(self):
        self.s.dpkg({"nginx": "1.32.0-1"})
        self.assertEqual(results(self.s.check("nginx-123007")), ["info"])

    def test_older_stable_is_affected_not_review(self):
        self.s.dpkg({"nginx": "1.24.0-1"})
        c = self.s.check("nginx-123007")
        self.assertEqual(results(c), ["affected"])
        self.assertNotIn("not covered by the source", c["findings"][0]["detail"])

    def test_vendor_suffix_below_floor_notes_backport(self):
        self.s.dpkg({"nginx": "1.24.0-1ubuntu1"})
        c = self.s.check("nginx-123007")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("backport", c["findings"][0]["detail"])

    def test_nginx_core_package(self):
        self.s.dpkg({"nginx-core": "1.30.6-1"})
        self.assertEqual(results(self.s.check("nginx-123007")), ["affected"])

    def test_openresty_is_review(self):
        self.s.dpkg({"openresty": "1.27.1-1"})
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_nginx_plus_is_review(self):
        self.s.dpkg({"nginx-plus": "37.0.8-1"})
        self.assertEqual(results(self.s.check("nginx-123007")), ["review"])

    def test_cellar_formula(self):
        m = self.sim("darwin")
        m.mkdir("/opt/homebrew/Cellar/nginx/1.30.6")
        c = m.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_binary_banner_not_executed(self):
        self.s.write("/usr/sbin/nginx", b"\x7fELF" + b"\x00" * 64 + b"nginx/1.30.6" + b"\x00" * 32)
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "1.30.6")

    def test_unversioned_binary_is_unknown(self):
        self.s.write("/usr/sbin/nginx", b"\x7fELF" + b"\x00" * 128)
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_windows_pe_version(self):
        w = self.sim("windows")
        w.write("C:/nginx/nginx.exe", hostfix.pe_with_version(hostfix.dotted(1, 30, 6, 0)))
        c = w.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_registry_oss_is_classified(self):
        w = self.sim("windows")
        c = w.check("nginx-123007", registry=[{"name": "nginx", "version": "1.30.6"}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_registry_plus_is_review(self):
        w = self.sim("windows")
        c = w.check("nginx-123007", registry=[{"name": "nginx Plus", "version": "R37"}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_windows_registry_plus_empty_version_is_review(self):
        w = self.sim("windows")
        c = w.check("nginx-123007", registry=[{"name": "NGINX Plus R37", "version": ""}])
        self.assertEqual(results(c), ["review"])

    def test_image_patch_level(self):
        self.s.write("~/code/web/Dockerfile", "FROM nginx:1.30.6\n")
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_moving_minor_tag_is_unknown(self):
        self.s.write("~/code/web/Dockerfile", "FROM nginx:1.30\n")
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_digest_pinned_is_unknown(self):
        digest = "b" * 64
        self.s.write("~/code/web/Dockerfile", "FROM nginx:1.30.7@sha256:%s\n" % digest)
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_openresty_image_is_review(self):
        tag = dotted(1, 27, 1, 1) + "-jammy"
        self.s.write("~/code/web/Dockerfile", "FROM openresty/openresty:%s\n" % tag)
        self.assertEqual(results(self.s.check("nginx-123007")), ["review"])

    def test_exporter_image_is_not_this_check(self):
        self.s.write("~/code/web/Dockerfile", "FROM nginx/nginx-prometheus-exporter:1.4.2\n")
        self.assertStatus(self.s.check("nginx-123007"), "NOT_APPLICABLE")

    def test_compose_environment_is_not_an_image(self):
        self.s.write("~/code/web/compose.yml",
                     "services:\n  web:\n    image: postgres:16\n    environment:\n"
                     "      image: nginx:1.30.6\n")
        self.assertStatus(self.s.check("nginx-123007"), "NOT_APPLICABLE")

    def test_unprivileged_image_is_oss(self):
        self.s.write("~/code/web/Dockerfile", "FROM nginxinc/nginx-unprivileged:1.30.6\n")
        self.assertEqual(results(self.s.check("nginx-123007")), ["affected"])


if __name__ == "__main__":
    unittest.main()
