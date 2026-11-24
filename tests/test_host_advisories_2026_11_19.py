"""Fixture tests for the 19 Nov 2026 host-check watch.

Synthetic hosts only. Nothing here executes nginx, LiteLLM, python or any
audited program. No PoC payloads, no credential values, no network.
"""

import json
import os
import subprocess
import unittest
from unittest import mock

import hostfix
import host_checks as hc

CAN_SYMLINK = hasattr(os, "symlink") and os.name != "nt"

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
        self.assertEqual(len(hc.CHECK_IDS), 87)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        self.assertIn("litellm-40217", hc.CHECK_IDS)
        self.assertIn("nginx-123007", hc.CHECK_IDS)
        self.assertIn("axis-90436", hc.CHECK_IDS)
        self.assertIn("litellm-1-107-0", hc.CHECK_IDS)
        self.assertIn("nginx-present", hc.CHECK_IDS)
        self.assertIn("ruby2shell", hc.CHECK_IDS)
        self.assertIn("php-129289", hc.CHECK_IDS)
        self.assertIn("drupal-132165", hc.CHECK_IDS)
        self.assertIn("ruby-regex", hc.CHECK_IDS)
        self.assertIn("php2shell", hc.CHECK_IDS)
        self.assertIn("drupal-commerce-118539", hc.CHECK_IDS)
        self.assertNotIn("litellm-40217", hc.INDICATOR_CHECKS)
        self.assertNotIn("nginx-123007", hc.INDICATOR_CHECKS)
        self.assertNotIn("ruby2shell", hc.INDICATOR_CHECKS)
        self.assertNotIn("php-129289", hc.INDICATOR_CHECKS)
        self.assertNotIn("drupal-132165", hc.INDICATOR_CHECKS)
        for cid in ("litellm-40217", "nginx-123007", "ruby2shell", "php-129289", "drupal-132165"):
            meta = next(m for m in hc.CHECKS if m["id"] == cid)
            self.assertTrue(meta["uses_walk"], cid)
            self.assertTrue(meta["sources"], cid)

    def test_skipped_rows_name_non_host_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("CVE-2024-10441", blob)
        self.assertIn("CVE-2026-90817", blob)
        self.assertIn("BIG-IP", blob)
        self.assertIn("Oyster", blob)
        self.assertIn("CVE-2026-115560 as a second check", blob)
        self.assertIn("CVE-2026-116331", blob)
        self.assertIn("CVE-2026-101786", blob)
        self.assertIn("ClickHouse Depthfirst", blob)
        self.assertIn("Oracle Text", blob)
        self.assertIn("European Commission", blob)
        self.assertIn("Mail Assure", blob)


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

    def test_banner_plain_floor_is_info(self):
        self.s.write("/usr/sbin/nginx", b"\x7fELF" + b"\x00" * 64 + b"nginx/1.30.7" + b"\x00" * 32)
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_banner_prerelease_of_stable_floor_is_affected(self):
        self.s.write("/usr/sbin/nginx", b"\x7fELF" + b"\x00" * 64 + b"nginx/1.30.7rc1" + b"\x00" * 32)
        c = self.s.check("nginx-123007")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "1.30.7rc1")
        self.assertIn("prerelease", c["findings"][0]["detail"])

    def test_banner_prerelease_of_mainline_floor_is_affected(self):
        self.s.write("/usr/sbin/nginx", b"\x7fELF" + b"\x00" * 64 + b"nginx/1.31.9rc1" + b"\x00" * 32)
        self.assertEqual(results(self.s.check("nginx-123007")), ["affected"])

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

    def test_windows_registry_openresty_is_review(self):
        w = self.sim("windows")
        c = w.check("nginx-123007", registry=[{"name": "OpenResty", "version": "1.27.1"}])
        self.assertStatus(c, "FAIL")
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


class Ruby2shell(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("ruby2shell"), "NOT_APPLICABLE")

    def test_prior_regex_floor_is_now_affected(self):
        self.s.mkdir("~/.rbenv/versions/4.0.9")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        regex = self.sim("linux")
        regex.mkdir("~/.rbenv/versions/4.0.9")
        self.assertEqual(results(regex.check("ruby-regex")), ["info"])

    def test_floors_are_info(self):
        for ver in ("4.0.10", "3.4.13", "3.3.14"):
            s = self.sim("linux")
            s.mkdir("~/.rbenv/versions/" + ver)
            c = s.check("ruby2shell")
            self.assertStatus(c, "PASS")
            self.assertEqual(results(c), ["info"], ver)

    def test_just_below_each_floor(self):
        for ver in ("4.0.9", "3.4.12", "3.3.13"):
            s = self.sim("linux")
            s.mkdir("~/.rbenv/versions/" + ver)
            self.assertEqual(results(s.check("ruby2shell")), ["affected"], ver)

    def test_eol_32_and_older_are_affected(self):
        for ver in ("3.2.9", "3.1.6", "2.7.8"):
            s = self.sim("linux")
            s.mkdir("~/.rbenv/versions/" + ver)
            c = s.check("ruby2shell")
            self.assertEqual(results(c), ["affected"], ver)
            self.assertIn("no fix", c["findings"][0]["detail"].lower())

    def test_newer_train_is_info(self):
        self.s.mkdir("~/.rbenv/versions/4.1.0")
        self.assertEqual(results(self.s.check("ruby2shell")), ["info"])

    def test_prerelease_of_floor_is_affected(self):
        self.s.mkdir("~/.rbenv/versions/4.0.10-rc1")
        c = self.s.check("ruby2shell")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("prerelease", c["findings"][0]["detail"])

    def test_dpkg_and_homebrew(self):
        self.s.dpkg({"ruby3.3": "3.3.13-1"})
        self.assertEqual(results(self.s.check("ruby2shell")), ["affected"])
        m = self.sim("darwin")
        m.mkdir("/opt/homebrew/Cellar/ruby/3.4.12")
        self.assertEqual(results(m.check("ruby2shell")), ["affected"])

    def test_image_tag_below_floor(self):
        self.s.write("~/code/app/Dockerfile", "FROM ruby:3.3.13\n")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_digest_pinned_is_unknown(self):
        digest = "c" * 64
        self.s.write("~/code/app/Dockerfile", "FROM ruby:3.3.14@sha256:%s\n" % digest)
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_moving_tag_is_unknown(self):
        self.s.write("~/code/app/Dockerfile", "FROM ruby:3.3\n")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_gitlab_bundled_ruby_is_info_only(self):
        self.s.write("/opt/gitlab/version-manifest.txt", "gitlab-ee 19.6.0\nruby 3.3.13\nomnibus-gitlab 19.6.0\n")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["info"])
        self.assertIn("vendor-bundled", c["findings"][0]["detail"])
        self.assertIn("not classified", c["reason"])

    def test_gitlab_ruby_blocks_even_with_patched_upstream(self):
        self.s.mkdir("~/.rbenv/versions/4.0.10")
        self.s.write("/opt/gitlab/version-manifest.txt", "gitlab-ee 19.6.0\nruby 3.3.13\nomnibus-gitlab 19.6.0\n")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["info", "info"])
        self.assertIn("not classified", c["reason"])

    def test_gitlab_does_not_hide_affected_upstream(self):
        self.s.mkdir("~/.rbenv/versions/4.0.9")
        self.s.write("/opt/gitlab/version-manifest.txt", "gitlab-ee 19.6.0\nruby 3.3.13\nomnibus-gitlab 19.6.0\n")
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))
        self.assertIn("also incomplete", c["reason"])

    def test_dpkg_ruby_metapackage_does_not_override_interpreter(self):
        self.s.dpkg({"ruby": "1:3.3+b1", "ruby3.3": "3.3.14-1"})
        c = self.s.check("ruby2shell")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_dpkg_ruby_metapackage_alone_is_not_this_check(self):
        self.s.dpkg({"ruby": "1:3.3+b1"})
        self.assertStatus(self.s.check("ruby2shell"), "NOT_APPLICABLE")

    def test_apk_ruby_is_the_interpreter(self):
        self.s.apk({"ruby": "3.3.13-r0"})
        self.assertEqual(results(self.s.check("ruby2shell")), ["affected"])
        ok = self.sim("linux")
        ok.apk({"ruby": "3.3.14-r0"})
        c = ok.check("ruby2shell")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_never_starts_ruby(self):
        self.s.mkdir("~/.rbenv/versions/3.3.13")
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("exec")) as popen, \
                mock.patch.object(os, "system", side_effect=AssertionError("exec")) as system:
            c = self.s.check("ruby2shell")
        popen.assert_not_called()
        system.assert_not_called()
        self.assertNotIn("check error", c["reason"])
        self.assertStatus(c, "FAIL")


class Php129289(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("php-129289"), "NOT_APPLICABLE")

    def test_prior_php2shell_floor_is_now_affected(self):
        self.s.dpkg({"php8.4-fpm": "8.4.27-1"})
        c = self.s.check("php-129289")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        old = self.sim("linux")
        old.dpkg({"php8.4-cli": "8.4.27-1"})
        old.write("/etc/php/8.4/cli/php.ini", "session.upload_progress.enabled = 0\n")
        self.assertStatus(old.check("php2shell"), "PASS")

    def test_floors_are_info(self):
        for pkg, ver in (("php8.5-fpm", "8.5.13-1"), ("php8.4-fpm", "8.4.28-1"),
                         ("php8.3-fpm", "8.3.37-1"), ("php8.2-fpm", "8.2.36-1")):
            s = self.sim("linux")
            s.dpkg({pkg: ver})
            c = s.check("php-129289")
            self.assertStatus(c, "PASS")
            self.assertEqual(results(c), ["info"], ver)

    def test_just_below_each_floor(self):
        for pkg, ver in (("php8.5-cli", "8.5.12-1"), ("php8.4-cli", "8.4.27-1"),
                         ("php8.3-cli", "8.3.36-1"), ("php8.2-cli", "8.2.35-1")):
            s = self.sim("linux")
            s.dpkg({pkg: ver})
            self.assertEqual(results(s.check("php-129289")), ["affected"], ver)

    def test_php86_is_info(self):
        self.s.dpkg({"php8.6-cli": "8.6.0-1"})
        self.assertEqual(results(self.s.check("php-129289")), ["info"])

    def test_php81_is_review(self):
        self.s.dpkg({"php8.1-cli": "8.1.32-1"})
        c = self.s.check("php-129289")
        self.assertEqual(results(c), ["review"])

    def test_vendor_suffix_notes_backport(self):
        self.s.dpkg({"php8.4-fpm": "8.4.27-1ubuntu1"})
        c = self.s.check("php-129289")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("backport", c["findings"][0]["detail"])

    def test_does_not_classify_php_ini(self):
        self.s.dpkg({"php8.4-fpm": "8.4.28-1"})
        self.s.write("/etc/php/8.4/fpm/php.ini", "session.upload_progress.enabled = 1\n")
        c = self.s.check("php-129289")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])
        for f in c["findings"]:
            self.assertNotIn("upload_progress", f["detail"])

    def test_image_tag_below_floor(self):
        self.s.write("~/code/web/Dockerfile", "FROM php:8.4.27-fpm-bookworm\n")
        c = self.s.check("php-129289")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_digest_pinned_is_unknown(self):
        digest = "d" * 64
        self.s.write("~/code/web/Dockerfile", "FROM php:8.4.28@sha256:%s\n" % digest)
        c = self.s.check("php-129289")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_moving_tag_is_unknown(self):
        self.s.write("~/code/web/Dockerfile", "FROM php:8.4\n")
        c = self.s.check("php-129289")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_compose_environment_image_is_not_an_image(self):
        self.s.write("~/code/web/compose.yml",
                     "services:\n  web:\n    image: nginx:1.30.7\n    environment:\n"
                     "      image: php:8.4.27\n")
        self.assertStatus(self.s.check("php-129289"), "NOT_APPLICABLE")

    def test_never_starts_php_fpm(self):
        self.s.dpkg({"php8.4-fpm": "8.4.27-1"})
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("exec")) as popen, \
                mock.patch.object(os, "system", side_effect=AssertionError("exec")) as system:
            c = self.s.check("php-129289")
        popen.assert_not_called()
        system.assert_not_called()
        self.assertNotIn("check error", c["reason"])
        self.assertStatus(c, "FAIL")

    def test_dpkg_php_metapackage_does_not_override_runtime(self):
        self.s.dpkg({"php": "2:8.4+96", "php-fpm": "2:8.4+96", "php8.4-fpm": "8.4.28-1"})
        c = self.s.check("php-129289")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_dpkg_php_metapackage_alone_is_not_this_check(self):
        self.s.dpkg({"php": "2:8.4+96", "php-fpm": "2:8.4+96"})
        self.assertStatus(self.s.check("php-129289"), "NOT_APPLICABLE")

    def test_apk_php_is_the_runtime(self):
        self.s.apk({"php": "8.4.27-r0"})
        self.assertEqual(results(self.s.check("php-129289")), ["affected"])
        ok = self.sim("linux")
        ok.apk({"php": "8.4.28-r0"})
        c = ok.check("php-129289")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])


class Drupal132165(SimCase):
    def _lock(self, spec, version, name="drupal/core", host=None):
        host = host or self.s
        host.write(spec, json.dumps({"packages": [{"name": name, "version": version}]}))

    def _core_php(self, root, version, host=None):
        s = host or self.s
        s.write(root + "/index.php", "<?php\n")
        s.write(root + "/core/lib/Drupal.php", "<?php\nclass Drupal {\n  const VERSION = '%s';\n}\n" % version)

    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("drupal-132165"), "NOT_APPLICABLE")

    def test_lock_below_106_floor(self):
        self._lock("~/sites/d10/composer.lock", "10.6.21")
        c = self.s.check("drupal-132165")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_lock_at_floors(self):
        for ver in ("10.6.22", "11.3.22", "11.4.13"):
            s = self.sim("linux")
            self._lock("~/sites/app/composer.lock", ver, host=s)
            c = s.check("drupal-132165")
            self.assertStatus(c, "PASS")
            self.assertEqual(results(c), ["info"], ver)

    def test_lock_just_below_114_and_113(self):
        for ver in ("11.4.12", "11.3.21"):
            s = self.sim("linux")
            self._lock("~/sites/app/composer.lock", ver, host=s)
            self.assertEqual(results(s.check("drupal-132165")), ["affected"], ver)

    def test_eol_lines_are_affected(self):
        for ver in ("11.2.8", "10.5.11", "9.5.11"):
            s = self.sim("linux")
            self._lock("~/sites/app/composer.lock", ver, host=s)
            c = s.check("drupal-132165")
            self.assertEqual(results(c), ["affected"], ver)
            self.assertIn("no fix", c["findings"][0]["detail"].lower())

    def test_newer_train_is_info(self):
        self._lock("~/sites/app/composer.lock", "12.0.0")
        self.assertEqual(results(self.s.check("drupal-132165")), ["info"])

    def test_recommended_package(self):
        self._lock("~/sites/app/composer.lock", "10.6.21", name="drupal/core-recommended")
        self.assertEqual(results(self.s.check("drupal-132165")), ["affected"])

    def test_composer_json_is_not_evidence(self):
        self.s.write("~/sites/app/composer.json", json.dumps({"require": {"drupal/core": "10.6.21"}}))
        self.assertStatus(self.s.check("drupal-132165"), "NOT_APPLICABLE")

    def test_drupal_php_version(self):
        self._core_php("~/sites/www", "11.4.12")
        c = self.s.check("drupal-132165")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        self._core_php("~/sites/www", "11.4.13", host=ok)
        self.assertEqual(results(ok.check("drupal-132165")), ["info"])

    def test_installed_json(self):
        self.s.write("~/sites/app/vendor/composer/installed.json",
                     json.dumps({"packages": [{"name": "drupal/core", "version": "10.6.21"}]}))
        self.assertEqual(results(self.s.check("drupal-132165")), ["affected"])

    def test_dev_build_is_review(self):
        self._lock("~/sites/app/composer.lock", "11.4.13-dev")
        c = self.s.check("drupal-132165")
        self.assertEqual(results(c), ["review"])

    def test_image_tag_below_floor(self):
        self.s.write("~/code/web/Dockerfile", "FROM drupal:10.6.21\n")
        c = self.s.check("drupal-132165")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_digest_pinned_is_unknown(self):
        digest = "e" * 64
        self.s.write("~/code/web/Dockerfile", "FROM drupal:10.6.22@sha256:%s\n" % digest)
        c = self.s.check("drupal-132165")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_never_http_or_exec(self):
        self._lock("~/sites/app/composer.lock", "10.6.21")
        self.s.write("~/sites/app/web/core/install.php", "<?php\n")
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network")) as connect, \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("exec")) as popen, \
                mock.patch.object(os, "system", side_effect=AssertionError("exec")) as system:
            c = self.s.check("drupal-132165")
        connect.assert_not_called()
        popen.assert_not_called()
        system.assert_not_called()
        self.assertNotIn("check error", c["reason"])
        self.assertStatus(c, "FAIL")
        for f in c["findings"]:
            self.assertNotIn("install.php", (f.get("path") or "").lower())

    @unittest.skipUnless(CAN_SYMLINK, "needs POSIX symlinks")
    def test_symlink_core_is_not_indexed(self):
        real = self.s.mkdir("~/elsewhere/core")
        self.s.write("~/elsewhere/core/lib/Drupal.php",
                     "<?php\nclass Drupal {\n  const VERSION = '11.4.12';\n}\n")
        self.s.write("~/sites/www/index.php", "<?php\n")
        os.symlink(real, self.s.path("~/sites/www/core"))
        self.assertStatus(self.s.check("drupal-132165"), "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
