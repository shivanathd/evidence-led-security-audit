"""Fixture tests for the 18 Nov 2026 host-check catch-up.

Synthetic hosts only. Nothing here executes an audited program or touches
the real home folder. IOC file contents are the vendor-published .pth lines
(hash-stable) or arbitrary bytes; no webhook URL and no secret values.
"""

import hashlib
import json
import os
import socket
import subprocess
import unittest
from unittest import mock

import hostfix
import host_checks as hc

results = hostfix.results
APP = getattr(hostfix, "APP")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


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


def _pth(line):
    return (line + "\n").encode("ascii")


class Catalog(SimCase):
    def test_new_ids_and_count(self):
        self.assertEqual(len(hc.CHECK_IDS), 88)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        for cid in ("artex-gateway-keys", "vcenter-log4shell", "axis-90436", "ncentral-hf3",
                    "blank-canvas-vsx", "apple-65339", "agent-framework-1-26",
                    "java4shell-114938", "puppet-115731", "roller-129448", "mysql-114952"):
            self.assertIn(cid, hc.CHECK_IDS)
        self.assertIn("artex-gateway-keys", hc.INDICATOR_CHECKS)
        self.assertIn("blank-canvas-vsx", hc.INDICATOR_CHECKS)
        self.assertIn("agent-framework-1-26", hc.INDICATOR_CHECKS)
        for cid in ("vcenter-log4shell", "axis-90436", "ncentral-hf3", "apple-65339",
                    "java4shell-114938", "puppet-115731", "roller-129448", "mysql-114952"):
            self.assertNotIn(cid, hc.INDICATOR_CHECKS)
        for cid in ("ncentral-hf3", "java4shell-114938", "axis-90436", "mysql-114952"):
            meta = next(m for m in hc.CHECKS if m["id"] == cid)
            self.assertTrue(meta["uses_walk"], cid)
        for m in hc.CHECKS:
            for key in m["sources"]:
                self.assertIn(key, hc.SRC)
                self.assertTrue(hc.SRC[key][1].startswith("https://"), key)

    def test_blank_canvas_id_set(self):
        self.assertEqual(len(hc.BLANK_CANVAS_VSX), 131)
        self.assertIn("tiroappteam.tiro-application-toolkits", hc.BLANK_CANVAS_VSX)
        self.assertIn("jonnyclyde.rojo-syncs", hc.BLANK_CANVAS_VSX)
        self.assertIn("jonnyclyde.open-board", hc.BLANK_CANVAS_VSX)
        self.assertNotIn("docsflowy.docsflowy", hc.BLANK_CANVAS_VSX)
        dump = " ".join(hc.BLANK_CANVAS_VSX)
        banned = "webhook" + ".site"
        self.assertNotIn(banned, dump)

    def test_no_webhook_or_default_master_key_in_module(self):
        with open(hc.__file__, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("webhook" + ".site", text)
        self.assertNotIn("sk-1234", text)
        self.assertNotIn("d381fd80", text)


class ArtexGatewayKeys(SimCase):
    def test_empty_is_pass(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("artex-gateway-keys"), "PASS")

    def test_litellm_config_field_name_is_review_value_withheld(self):
        self.s.write("~/.litellm/config.yaml", "master_key: super-secret-value-not-for-output\nmodel_list: []\n")
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        blob = json.dumps(c)
        self.assertIn("master_key", blob)
        self.assertNotIn("super-secret-value-not-for-output", blob)

    def test_one_api_env_names_only(self):
        env_name = "SESSION_" + "SECRET"
        self.s.write("/opt/one-api/.env", "SQL_DSN=hidden\n%s=hidden2\nPORT=3000\n" % env_name)
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "FAIL")
        blob = json.dumps(c)
        self.assertIn(env_name, blob)
        self.assertNotIn("hidden2", blob)
        self.assertNotIn("hidden", blob.split(env_name)[0][-20:])

    def test_dify_image_is_review(self):
        self.s.write("~/code/gw/compose.yml", "image: langgenius/dify-api:0.15.0\n")
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        blob = json.dumps(c)
        self.assertNotIn("langgenius/dify-api", blob)

    def test_compose_env_value_is_not_an_image(self):
        sentinel = "opaque-test-value/litellm"
        self.s.write("~/code/gw/compose.yml", "environment:\n  PROVIDER_TOKEN: %s\n" % sentinel)
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "PASS")
        self.assertNotIn(sentinel, json.dumps(c))

    def test_from_alpine_as_litellm_is_not_an_image(self):
        self.s.write("~/code/gw/Dockerfile", "FROM alpine AS litellm\n")
        self.assertStatus(self.s.check("artex-gateway-keys"), "PASS")

    def test_quoted_field_name_is_review_value_withheld(self):
        self.s.write("~/.litellm/config.yaml", '"master_key": "placeholder-not-for-output"\n')
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        blob = json.dumps(c)
        self.assertIn("master_key", blob)
        self.assertNotIn("placeholder-not-for-output", blob)

    def test_bare_password_field_is_review_value_withheld(self):
        self.s.write("~/.litellm/config.yaml", '"password": "placeholder-not-for-output"\n')
        c = self.s.check("artex-gateway-keys")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        blob = json.dumps(c)
        self.assertIn("password", blob)
        self.assertNotIn("placeholder-not-for-output", blob)

    def test_never_connects(self):
        self.s.write("~/.litellm/config.yaml", "litellm_settings:\n  drop_params: true\n")
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")) as conn:
            c = self.s.check("artex-gateway-keys")
        conn.assert_not_called()
        self.assertNotIn("check error", c["reason"])


class VcenterLog4shell(SimCase):
    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("vcenter-log4shell"), "NOT_APPLICABLE")

    def test_linux_package_below_floor_is_affected(self):
        self.s.dpkg({"vmware-vpx": "7.0.3.00100"})
        self.s.write("/etc/vmware-vpx/buildNumber", "19234500\n")
        c = self.s.check("vcenter-log4shell")
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))

    def test_build_at_7_0_u3c_is_info(self):
        self.s.dpkg({"vmware-vpx": "7.0.3.00300"})
        self.s.write("/etc/vmware-vpx/buildNumber", "19234570\n")
        c = self.s.check("vcenter-log4shell")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_v8_is_info(self):
        self.s.dpkg({"vmware-vpx": "8.0.2.00100"})
        c = self.s.check("vcenter-log4shell")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_dir_without_version_is_blocked(self):
        self.s.mkdir("/usr/lib/vmware-vpx")
        c = self.s.check("vcenter-log4shell")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])


class Axis90436(SimCase):
    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("axis-90436"), "NOT_APPLICABLE")

    def test_axis_jar_is_review(self):
        self.s.write("~/code/app/WEB-INF/lib/axis.jar", b"PK\x03\x04axis")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_confluence_9_2_27_affected_9_2_28_info(self):
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-9.2.27.jar", b"PK")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-9.2.28.jar", b"PK")
        c = ok.check("axis-90436")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_confluence_10_is_info(self):
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-10.0.2.jar", b"PK")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_image_tag(self):
        self.s.write("~/code/wiki/Dockerfile", "FROM atlassian/confluence-server:9.2.20\n")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_backup_jar_is_not_patch_evidence(self):
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-9.2.28.jar.bak", b"PK")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_second_install_without_jar_is_unknown(self):
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-9.2.28.jar", b"PK")
        self.s.mkdir("/usr/local/atlassian/confluence")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "BLOCKED")
        self.assertIn("unknown", results(c))
        self.assertIn("info", results(c))

    def test_fixed_jar_does_not_hide_below_floor_jar(self):
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-10.0.2.jar", b"PK")
        self.s.write("/opt/atlassian/confluence/confluence/WEB-INF/lib/confluence-9.2.27.jar", b"PK")
        c = self.s.check("axis-90436")
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))


class NcentralHf3(SimCase):
    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("ncentral-hf3"), "NOT_APPLICABLE")

    def test_hf2_affected_hf3_info(self):
        self.s.dpkg({"n-central": "2026.4.1.26"})
        c = self.s.check("ncentral-hf3")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.dpkg({"n-central": "2026.4.1.39"})
        c = ok.check("ncentral-hf3")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_windows_version_file(self):
        w = self.sim("windows")
        w.write("C:/Program Files/N-able/N-central/ncentral.version", "2026.4.1.26\n")
        c = w.check("ncentral-hf3")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_linux_dir_without_version_is_blocked(self):
        self.s.mkdir("/opt/n-able/n-central")
        c = self.s.check("ncentral-hf3")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_second_windows_install_without_version_is_unknown(self):
        w = self.sim("windows")
        w.write("C:/Program Files/N-able/N-central/ncentral.version", "2026.4.1.39\n")
        w.mkdir("C:/Program Files (x86)/N-able/N-central")
        c = w.check("ncentral-hf3")
        self.assertStatus(c, "BLOCKED")
        self.assertIn("unknown", results(c))
        self.assertIn("info", results(c))

    def test_whitespace_version_file_does_not_stop_later_root(self):
        self.s.write("/opt/n-able/n-central/ncentral.version", "\n")
        self.s.write("/opt/nable/n-central/ncentral.version", "2026.4.1.26\n")
        c = self.s.check("ncentral-hf3")
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))
        self.assertNotIn("check error", c["reason"])


class BlankCanvasVsx(SimCase):
    def test_empty_is_pass(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("blank-canvas-vsx"), "PASS")

    def test_tiro_folder_is_affected(self):
        self.s.write("~/.vscode/extensions/tiroappteam.tiro-application-toolkits-1.0.0/package.json",
                     '{"name":"tiro-application-toolkits","publisher":"TiroAppTeam","version":"1.0.0"}\n')
        c = self.s.check("blank-canvas-vsx")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_unrelated_extension_is_ignored(self):
        self.s.write("~/.cursor/extensions/anthropic.claude-code-2.1.400/package.json",
                     '{"name":"claude-code","version":"2.1.400"}\n')
        self.assertStatus(self.s.check("blank-canvas-vsx"), "PASS")

    def test_jonny_open_board(self):
        self.s.write("~/.vscode/extensions/jonnyclyde.open-board-0.2.1/package.json", "{}")
        self.assertEqual(results(self.s.check("blank-canvas-vsx")), ["affected"])

    def test_id_prefix_without_version_suffix_is_ignored(self):
        self.s.write("~/.vscode/extensions/jonnyclyde.open-board-notes/package.json", "{}")
        self.assertStatus(self.s.check("blank-canvas-vsx"), "PASS")

    def test_open_board_2fa_is_not_listed_id(self):
        self.s.write("~/.vscode/extensions/jonnyclyde.open-board-2fa-1.0.0/package.json", "{}")
        self.assertStatus(self.s.check("blank-canvas-vsx"), "PASS")

    def test_platform_suffix_still_matches(self):
        self.s.write("~/.vscode/extensions/jonnyclyde.open-board-0.2.1-linux-x64/package.json", "{}")
        self.assertEqual(results(self.s.check("blank-canvas-vsx")), ["affected"])
        ok = self.sim("linux")
        ok.write("~/.vscode/extensions/jonnyclyde.open-board-0.2.1-universal/package.json", "{}")
        self.assertEqual(results(ok.check("blank-canvas-vsx")), ["affected"])


class Apple65339(SimCase):
    def _mac(self, os_ver):
        s = self.sim("darwin")
        s.plist("/System/Library/CoreServices/SystemVersion.plist", {"ProductVersion": os_ver})
        return s.check("apple-65339")

    def test_linux_windows_not_applicable(self):
        self.assertStatus(self.sim("linux").check("apple-65339"), "NOT_APPLICABLE")
        self.assertStatus(self.sim("windows").check("apple-65339"), "NOT_APPLICABLE")

    def test_tahoe_26_6_1_affected_26_6_2_info(self):
        low = self._mac("26.6.1")
        self.assertStatus(low, "FAIL")
        self.assertEqual(results(low), ["affected"])
        ok = self._mac("26.6.2")
        self.assertStatus(ok, "PASS")
        self.assertEqual(results(ok), ["info"])

    def test_sequoia_15_7_affected_15_8_info(self):
        low = self._mac("15.7.1")
        self.assertEqual(results(low), ["affected"])
        self.assertTrue(any("HT149043" in f["detail"] for f in low["findings"]))
        ok = self._mac("15.8")
        self.assertEqual(results(ok), ["info"])
        self.assertTrue(any("HT149043" in f["detail"] for f in ok["findings"]))
        self.assertFalse(any("HT148281" in f["detail"] for f in ok["findings"]))

    def test_sonoma_14_is_review(self):
        c = self._mac("14.7.2")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_27_is_info(self):
        self.assertStatus(self._mac("27.0"), "PASS")
        self.assertEqual(results(self._mac("27.0")), ["info"])

    def test_darwin_without_productversion_is_unknown(self):
        c = self.sim("darwin").check("apple-65339")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])


class AgentFramework126(SimCase):
    def test_empty_is_pass(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("agent-framework-1-26"), "PASS")

    def test_installed_1_26_1_is_affected(self):
        self.s.venv("~/code/app/.venv", {"agent_framework": "1.26.1"})
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_installed_1_26_0_is_info(self):
        self.s.venv("~/code/app/.venv", {"agent_framework": "1.26.0"})
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_pth_hash_is_affected(self):
        body = _pth("import agent_framework_meta")
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e")
        self.s.write("~/code/app/.venv/pyvenv.cfg", "home = /usr/bin\n")
        self.s.write("~/code/app/.venv/lib/python3.12/site-packages/agent_framework_meta.pth", body)
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_named_file_wrong_hash_is_review(self):
        self.s.write("~/code/app/.venv/pyvenv.cfg", "home = /usr/bin\n")
        self.s.write("~/code/app/.venv/lib/python3.12/site-packages/af_runtime_diag.pth", b" innocuous\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_unpinned_sibling_is_review(self):
        self.s.write("~/code/app/requirements.txt", "agent-framework-openai\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_pinned_1_26_2(self):
        self.s.write("~/code/app/requirements.txt", "agent-framework==1.26.2\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_pinned_1_26_2_0_is_affected(self):
        pin = "agent-framework==%s\n" % hostfix.dotted(1, 26, 2, 0)
        self.s.write("~/code/app/requirements.txt", pin)
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_triple_equals_pin_is_not_identity(self):
        self.s.write("~/code/app/requirements.txt", "agent-framework===1.26.2\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_triple_equals_trailing_extra_zero_is_not_identity(self):
        pin = "agent-framework===%s\n" % hostfix.dotted(1, 26, 2, 0)
        self.s.write("~/code/app/requirements.txt", pin)
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_wildcard_equality_is_review(self):
        self.s.write("~/code/app/requirements.txt", "agent-framework==1.26.*\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_sibling_wildcard_is_review_not_malicious(self):
        self.s.write("~/code/app/requirements.txt", "agent-framework-openai==1.26.*\n")
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])
        self.assertNotIn("affected", results(c))

    def test_incomplete_py_installs_is_blocked(self):
        self.s.venv("~/code/app/.venv", {"pillow": "10.0.0"})
        host = self.s.host()
        hc.index(host)
        meta = next(m for m in hc.CHECKS if m["id"] == "agent-framework-1-26")
        with mock.patch.object(host.budget, "over", return_value=True):
            host._cache.pop("py_installs", None)
            host._cache.pop("py_installs_complete", None)
            c = hc.run_check(host, meta)
        self.assertStatus(c, "BLOCKED")
        self.assertIn("python environment scan stopped", c["reason"])

    @unittest.skipIf(os.name == "nt" or IS_ROOT, "chmod 000 does not block root or Windows")
    def test_unreadable_site_packages_is_blocked(self):
        self.s.venv("~/code/app/.venv", {"pillow": "10.0.0"})
        sp = self.s.path("~/code/app/.venv/lib/python3.12/site-packages")
        os.chmod(sp, 0)
        c = self.s.check("agent-framework-1-26")
        self.assertStatus(c, "BLOCKED")
        self.assertIn("python environment scan stopped", c["reason"])

    def test_output_has_no_webhook(self):
        self.s.venv("~/code/app/.venv", {"agent_framework": "1.26.2"})
        blob = json.dumps(self.s.check("agent-framework-1-26"))
        self.assertNotIn("webhook", blob.lower())
        self.assertNotIn("d381fd80", blob)


class Java4shell114938(SimCase):
    REL = 'JAVA_VERSION="%s"\nIMPLEMENTOR="Eclipse Adoptium"\n'

    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("java4shell-114938"), "NOT_APPLICABLE")

    def test_17_0_21_affected_17_0_21_1_info(self):
        self.s.write("/usr/lib/jvm/java-17-openjdk/release", self.REL % "17.0.21")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.write("/usr/lib/jvm/java-17-openjdk/release", self.REL % hostfix.dotted(17, 0, 21, 1))
        c = ok.check("java4shell-114938")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_17_0_5_not_this_cve(self):
        self.s.write("/usr/lib/jvm/java-17-openjdk/release", self.REL % "17.0.5")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_8_generic_is_info_8u511_perf_affected(self):
        self.s.write("/usr/lib/jvm/java-8-openjdk/release", self.REL % "1.8.0_422")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])
        bad = self.sim("linux")
        bad.write("/usr/lib/jvm/java-8-openjdk-perf/release", self.REL % "1.8.0_511-perf")
        c = bad.check("java4shell-114938")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        early = self.sim("linux")
        early.write("/usr/lib/jvm/java-8-openjdk-perf/release", self.REL % "1.8.0_510-perf")
        c = early.check("java4shell-114938")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_compact_8u511_perf_image_is_affected_bare_8_is_moving(self):
        self.s.write("~/code/app/Dockerfile", "FROM openjdk:8u511-perf\n")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        moving = self.sim("linux")
        moving.write("~/code/app/Dockerfile", "FROM openjdk:8\n")
        c = moving.check("java4shell-114938")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertIn("moving tag", c["findings"][0]["detail"])

    def test_eclipse_temurin_17_moving_tag_is_unknown(self):
        self.s.write("~/code/app/Dockerfile", "FROM eclipse-temurin:17\n")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertNotIn("at or above the fixed build", c["reason"])

    def test_homebrew_libexec_release(self):
        self.s.write("/opt/homebrew/Cellar/openjdk@17/17.0.21/libexec/openjdk.jdk/Contents/Home/release",
                     self.REL % "17.0.21")
        c = self.s.check("java4shell-114938")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_never_runs_java(self):
        self.s.write("/usr/lib/jvm/java-21-openjdk/release", self.REL % "21.0.12")

        def runner(argv, timeout=30):
            if any("java" in str(a).lower() for a in argv):
                raise AssertionError("ran java")
            return None

        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("exec")), \
                mock.patch.object(os, "system", side_effect=AssertionError("exec")):
            c = self.s.check("java4shell-114938", runner=runner)
        self.assertNotIn("check error", c["reason"])
        self.assertStatus(c, "FAIL")


class Puppet115731(SimCase):
    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("puppet-115731"), "NOT_APPLICABLE")

    def test_agent_8_22_0_affected_8_22_2_info(self):
        self.s.dpkg({"puppet-agent": "8.22.0-1"})
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.dpkg({"puppet-agent": "8.22.2-1"})
        self.assertEqual(results(ok.check("puppet-115731")), ["info"])

    def test_8_22_1_is_review(self):
        self.s.dpkg({"puppet-agent": "8.22.1-1"})
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_pe_2023_8_12_affected(self):
        self.s.write("/opt/puppetlabs/server/pe_version", "2023.8.12\n")
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_core_9_1_3_info(self):
        self.s.write("/opt/puppetlabs/puppet/VERSION", "9.1.3\n")
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_blank_pe_version_continues_to_core(self):
        self.s.write("/opt/puppetlabs/server/pe_version", "\n")
        self.s.write("/opt/puppetlabs/puppet/VERSION", "8.22.0\n")
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))
        self.assertNotIn("check error", c["reason"])

    @unittest.skipIf(os.name == "nt" or IS_ROOT, "chmod 000 does not block root or Windows")
    def test_unreadable_pe_version_is_unknown(self):
        pe = self.s.write("/opt/puppetlabs/server/pe_version", "2023.8.13\n")
        os.chmod(pe, 0)
        self.s.write("/opt/puppetlabs/puppet/VERSION", "8.22.2\n")
        c = self.s.check("puppet-115731")
        self.assertStatus(c, "BLOCKED")
        self.assertIn("unknown", results(c))
        self.assertTrue(any("not readable" in f["detail"] for f in c["findings"]))


class Roller129448(SimCase):
    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("roller-129448"), "NOT_APPLICABLE")

    def test_6_1_5_affected_6_1_6_info(self):
        self.s.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                     "ro.version=6.1.5\n")
        c = self.s.check("roller-129448")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                 "ro.version=6.1.6\n")
        self.assertEqual(results(ok.check("roller-129448")), ["info"])

    def test_web_xml_is_not_a_patch(self):
        self.s.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                     "ro.version=6.1.5\n")
        self.s.write("~/apps/roller/WEB-INF/web.xml", "<web-app><filter-name>CsrfFilter</filter-name></web-app>\n")
        c = self.s.check("roller-129448")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertTrue(any("mitigation" in f["detail"] for f in c["findings"]))

    def test_image_tag(self):
        self.s.write("~/code/blog/Dockerfile", "FROM apache/roller:6.1.5\n")
        self.assertEqual(results(self.s.check("roller-129448")), ["affected"])

    @unittest.skipIf(os.name == "nt" or IS_ROOT, "chmod 000 does not block root or Windows")
    def test_unreadable_properties_is_blocked(self):
        path = self.s.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                            "ro.version=6.1.5\n")
        os.chmod(path, 0)
        c = self.s.check("roller-129448")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_empty_version_key_is_unknown(self):
        self.s.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                     "ro.version=\n")
        c = self.s.check("roller-129448")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_version_file_without_key_is_unknown(self):
        self.s.write("~/apps/roller/WEB-INF/classes/org/apache/roller/version.properties",
                     "build.vendor=Apache\n")
        c = self.s.check("roller-129448")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_classes_root_roller_version_without_key_is_unknown(self):
        self.s.write("~/apps/roller/WEB-INF/classes/roller-version.properties",
                     "build.vendor=Apache\n")
        c = self.s.check("roller-129448")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])


class Mysql114952(SimCase):
    H = '#define MYSQL_SERVER_VERSION "%s"\n'

    def test_empty_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check("mysql-114952"), "NOT_APPLICABLE")

    def test_8_4_13_affected_8_4_14_info(self):
        self.s.dpkg({"mysql-server": "8.4.13-1"})
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        ok = self.sim("linux")
        ok.dpkg({"mysql-server": "8.4.14-1"})
        self.assertStatus(ok.check("mysql-114952"), "PASS")
        self.assertEqual(results(ok.check("mysql-114952")), ["info"])

    def test_mariadb_is_not_this_check(self):
        self.s.dpkg({"mariadb-server": "10.11.8-1", "mariadb": "10.11.8-1"})
        self.assertStatus(self.s.check("mysql-114952"), "NOT_APPLICABLE")

    def test_client_only_is_not_this_check(self):
        self.s.dpkg({"mysql-client": "8.4.13-1", "libmysqlclient21": "8.4.13-1"})
        self.assertStatus(self.s.check("mysql-114952"), "NOT_APPLICABLE")

    def test_26_10_affected_26_10_1_review(self):
        self.s.dpkg({"mysql-server": "26.10.0-1"})
        self.assertEqual(results(self.s.check("mysql-114952")), ["affected"])
        nxt = self.sim("linux")
        nxt.dpkg({"mysql-server": "26.10.1-1"})
        c = nxt.check("mysql-114952")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_cluster_8_0_50_affected(self):
        self.s.dpkg({"mysql-cluster-community-server": "8.0.50-1"})
        self.assertEqual(results(self.s.check("mysql-114952")), ["affected"])

    def test_cluster_glue_is_not_this_check(self):
        self.s.dpkg({"cluster-glue": "1.0.12-1"})
        self.assertStatus(self.s.check("mysql-114952"), "NOT_APPLICABLE")

    def test_moving_image_tag_is_unknown_not_pass(self):
        self.s.write("~/code/db/Dockerfile", "FROM mysql:latest\n")
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertNotIn("at or above the fixed build", c["reason"])

    def test_minor_line_tag_is_not_padded(self):
        self.s.write("~/code/db/compose.yml", "image: mysql:8.4\n")
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        patch = self.sim("linux")
        patch.write("~/code/db/compose.yml", "image: mysql:8.4.13\n")
        self.assertEqual(results(patch.check("mysql-114952")), ["affected"])

    def test_compose_env_mysql_token_is_not_an_image(self):
        self.s.write("~/code/db/compose.yml",
                     "services:\n  db:\n    image: postgres:16\n    environment:\n"
                     "      MYSQL_DOC_EXAMPLE: mysql:8.4.13\n")
        self.assertStatus(self.s.check("mysql-114952"), "NOT_APPLICABLE")

    def test_from_tab_is_an_image(self):
        self.s.write("~/code/db/Dockerfile", "FROM\tmysql:8.4.13 AS db\n")
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_quoted_compose_image_key(self):
        self.s.write("~/code/db/compose.yml", 'services:\n  db:\n    "image": mysql:8.4.13\n')
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_compose_environment_image_key_is_not_an_image(self):
        self.s.write("~/code/db/compose.yml",
                     "services:\n  db:\n    image: postgres:16\n    environment:\n"
                     "      image: mysql:8.4.13\n")
        self.assertStatus(self.s.check("mysql-114952"), "NOT_APPLICABLE")

    def test_digest_pinned_tag_is_unknown_not_patch(self):
        digest = "a" * 64
        self.s.write("~/code/db/Dockerfile", "FROM mysql:8.4.14@sha256:%s\n" % digest)
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertIn("digest-pinned", c["findings"][0]["detail"])
        self.assertNotIn("at or above the fixed build", c["reason"])

    def test_registry_port_tag_is_still_classified(self):
        self.s.write("~/code/db/Dockerfile", "FROM registry.example:5000/mysql:8.4.13\n")
        c = self.s.check("mysql-114952")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_fail_keeps_truncated_walk_on_evidence(self):
        meta = next(m for m in hc.CHECKS if m["id"] == "java4shell-114938")
        doc = {"checks": [{
            "id": "java4shell-114938", "title": meta["title"], "layer": meta["layer"],
            "status": "FAIL", "reason": "1 affected, 0 to review; home walk stopped early (max_entries)",
            "findings": [{"result": "affected", "component": "Java image", "version": "17.0.21"}],
            "scan_truncated": True,
        }]}
        frag = hc.report_fragments(doc, "dev-laptop", "2026-11-18")
        self.assertEqual(frag["evidence"][0]["collection_status"], "truncated")
        self.assertEqual(frag["required_checks"][0]["status"], "FAIL")

    def test_never_starts_mysql(self):
        self.s.dpkg({"mysql-server": "8.4.13-1"})

        def runner(argv, timeout=30):
            joined = " ".join(str(a) for a in argv).lower()
            if "mysql" in joined:
                raise AssertionError("ran mysql")
            return None

        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("exec")), \
                mock.patch.object(os, "system", side_effect=AssertionError("exec")):
            c = self.s.check("mysql-114952", runner=runner)
        self.assertNotIn("check error", c["reason"])
        self.assertStatus(c, "FAIL")


if __name__ == "__main__":
    unittest.main()
