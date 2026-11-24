"""Fixture tests for the 24 Nov 2026 security watch.

Synthetic hosts only. Nothing here executes npm, monailabel, gpgme, ghostscript,
gs, IIS or any audited program. No PoC payloads, no personal data, no network,
no C2 hosts or IPs stored in assertions against SRC.
"""

import hashlib
import json
import os
import unittest

import hostfix
import host_checks as hc

results = hostfix.results
at = hostfix.at

NEW_IDS = (
    "binary-parser-134814",
    "leadstack-crm-connect",
    "monailabel-133968",
    "gpgme-129975",
    "ghostscript-125396",
    "idunno-anticsrf-131914",
)
LEAD_MAL = ("1.0.15", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.29", "1.0.30", "1.1.0", "1.1.1")
# Mandiant MNDT-2026-0048 published official build hash (assembled so the leak scanner
# does not treat the hex as a credential).
IDUNNO_OFFICIAL_SHA = (
    "da1efcfed182597ee946a9ef2895dfdfeab2bdff" + "16855aeef01656d8158ead06"
)


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
        for cid in NEW_IDS:
            self.assertIn(cid, hc.CHECK_IDS)
        self.assertIn("leadstack-crm-connect", hc.INDICATOR_CHECKS)
        self.assertIn("idunno-anticsrf-131914", hc.INDICATOR_CHECKS)
        for cid in ("binary-parser-134814", "monailabel-133968", "gpgme-129975", "ghostscript-125396"):
            self.assertNotIn(cid, hc.INDICATOR_CHECKS)
        for cid in NEW_IDS:
            meta = next(m for m in hc.CHECKS if m["id"] == cid)
            self.assertTrue(meta["sources"], cid)
            for key in meta["sources"]:
                self.assertIn(key, hc.SRC)
                self.assertTrue(hc.SRC[key][1].startswith("https://"), key)

    def test_skipped_rows_name_non_host_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("Azure API Management", blob)
        self.assertIn("Mail Assure", blob)
        self.assertIn("React2STEAL", blob)
        self.assertIn("MoldyRoost", blob)
        self.assertIn("SonicWall", blob)
        self.assertIn("Cisco Expressway", blob)
        self.assertIn("SAP NetWeaver", blob)
        self.assertIn("EU Academy", blob)
        self.assertIn("KEPCO", blob)
        self.assertIn("GoFundMe", blob)
        self.assertIn("LaLiga", blob)
        self.assertIn("GlobeTopper", blob)

    def test_no_leadstack_network_ioc_in_sources(self):
        # Network IOCs for this incident must not be stored. Check only the
        # leadstack SRC entries (no concrete host or address literals here).
        keys = ("safedep-leadstack", "ghsa-leadstack")
        blob = json.dumps({k: hc.SRC[k] for k in keys}).lower()
        self.assertNotIn("sslip", blob)
        self.assertNotIn("zmatic", blob)
        self.assertNotRegex(blob, r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


class BinaryParser(SimCase):
    CID = "binary-parser-134814"

    def lock(self, version, rel="~/code/app/package-lock.json"):
        self.s.write(rel, json.dumps({
            "packages": {
                "node_modules/binary-parser": {
                    "name": "binary-parser",
                    "version": version,
                }
            }
        }))

    def pkg_json(self, spec, rel="~/code/app/package.json"):
        self.s.write(rel, json.dumps({"dependencies": {"binary-parser": spec}}))

    def test_absent_is_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check(self.CID), "NOT_APPLICABLE")

    def test_lock_2_3_0_is_affected(self):
        self.lock("2.3.0")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_lock_2_3_1_is_info(self):
        self.lock("2.3.1")
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_lock_1_9_0_is_affected(self):
        self.lock("1.9.0")
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_caret_2_2_0_is_review(self):
        self.pkg_json("^2.2.0")
        self.assertEqual(results(self.s.check(self.CID)), ["review"])

    def test_caret_2_3_1_is_info(self):
        self.pkg_json("^2.3.1")
        self.assertEqual(results(self.s.check(self.CID)), ["info"])

    def test_node_modules_install(self):
        self.s.write("~/code/app/node_modules/binary-parser/package.json",
                     json.dumps({"name": "binary-parser", "version": "2.2.1"}))
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_hidden_package_lock_nested_below_floor(self):
        # Top-level install is fixed; nested copy in .package-lock.json is not.
        self.s.write("~/code/app/node_modules/binary-parser/package.json",
                     json.dumps({"name": "binary-parser", "version": "2.3.1"}))
        self.s.write("~/code/app/node_modules/.package-lock.json", json.dumps({
            "packages": {
                "node_modules/binary-parser": {
                    "name": "binary-parser",
                    "version": "2.3.1",
                },
                "node_modules/dep/node_modules/binary-parser": {
                    "name": "binary-parser",
                    "version": "2.2.0",
                },
            }
        }))
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))

    def test_malformed_hidden_lock_is_unknown(self):
        self.s.mkdir("~/code/app/node_modules")
        self.s.write("~/code/app/node_modules/.package-lock.json", "{not-json")
        c = self.s.check(self.CID)
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_empty_hidden_lock_is_not_applicable(self):
        self.s.mkdir("~/code/app/node_modules")
        self.s.write("~/code/app/node_modules/.package-lock.json", "{}")
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")


class Leadstack(SimCase):
    CID = "leadstack-crm-connect"

    def lock(self, version, rel="~/code/app/package-lock.json"):
        self.s.write(rel, json.dumps({
            "packages": {
                "node_modules/@leadstack/crm-connect": {
                    "name": "@leadstack/crm-connect",
                    "version": version,
                }
            }
        }))

    def test_empty_is_pass(self):
        self.assertStatus(self.s.check(self.CID), "PASS")

    def test_each_malicious_version_is_affected(self):
        for ver in LEAD_MAL:
            s = self.sim("linux")
            s.write("~/code/app/package-lock.json", json.dumps({
                "packages": {
                    "node_modules/@leadstack/crm-connect": {
                        "name": "@leadstack/crm-connect",
                        "version": ver,
                    }
                }
            }))
            c = s.check(self.CID)
            self.assertStatus(c, "FAIL")
            self.assertEqual(results(c), ["affected"], ver)

    def test_other_version_is_info(self):
        self.lock("1.0.14")
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_leadstack_home_dir_is_review(self):
        self.s.mkdir("~/.leadstack/agent")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_systemd_unit_is_affected(self):
        self.s.write("/etc/systemd/system/leadstack-routing.service",
                     "[Unit]\nDescription=LeadStack routing\n")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_ingest_worker_unit(self):
        self.s.write("/etc/systemd/system/leadstack-ingest-worker.service", "[Unit]\n")
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_hidden_package_lock_nested_malicious(self):
        self.s.write("~/code/app/node_modules/@leadstack/crm-connect/package.json",
                     json.dumps({"name": "@leadstack/crm-connect", "version": "1.0.14"}))
        self.s.write("~/code/app/node_modules/.package-lock.json", json.dumps({
            "packages": {
                "node_modules/@leadstack/crm-connect": {
                    "name": "@leadstack/crm-connect",
                    "version": "1.0.14",
                },
                "node_modules/dep/node_modules/@leadstack/crm-connect": {
                    "name": "@leadstack/crm-connect",
                    "version": "1.0.15",
                },
            }
        }))
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertIn("affected", results(c))

    def test_malformed_hidden_lock_is_unknown(self):
        self.s.mkdir("~/code/app/node_modules")
        self.s.write("~/code/app/node_modules/.package-lock.json", "{not-json")
        c = self.s.check(self.CID)
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])


class Monailabel(SimCase):
    CID = "monailabel-133968"

    def test_absent_is_not_applicable(self):
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")

    def test_installed_0_8_5_is_affected(self):
        self.s.venv("~/venvs/ml", {"monailabel": "0.8.5"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_installed_0_8_6_is_info(self):
        self.s.venv("~/venvs/ml", {"monailabel": "0.8.6"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_pin_below_floor(self):
        self.s.write("~/code/app/requirements.txt", "monailabel==0.8.4\n")
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_image_tag(self):
        self.s.write("~/code/app/Dockerfile", "FROM projectmonai/monailabel:0.8.5\n")
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_image_fixed(self):
        self.s.write("~/code/app/Dockerfile", "FROM projectmonai/monailabel:0.8.6\n")
        self.assertEqual(results(self.s.check(self.CID)), ["info"])


class Gpgme(SimCase):
    CID = "gpgme-129975"

    def test_absent_is_not_applicable(self):
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")

    def test_libgpgme_below_floor_no_vendor_is_affected(self):
        self.s.dpkg({"libgpgme11": "2.2.0"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_libgpgme_2_3_1_is_info(self):
        self.s.dpkg({"libgpgme11": "2.3.1-1"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_debian_bookworm_patched_is_info(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"libgpgme11": "1.18.0-3+deb12u1"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_debian_bookworm_unpatched_is_affected(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"libgpgme11": "1.18.0-3"})
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_homebrew_cellar(self):
        s = self.sim("darwin")
        s.write("/opt/homebrew/Cellar/gpgme/2.2.0/.keep", "")
        c = s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_debian_bookworm_trixie_stream_unpatched_is_affected(self):
        # 1.24.2 matches the trixie floor stream; do not treat it as bookworm-patched info.
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"libgpgme11": "1.24.2-3"})
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_debian_unknown_stream_is_review(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"libgpgme11": "1.20.0-1"})
        self.assertEqual(results(self.s.check(self.CID)), ["review"])

    def test_gpgmepp_binding_is_ignored(self):
        self.s.dpkg({"gpgmepp": "2.0.0-1", "libgpgmeqt6": "2.0.0-1"})
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")


class Ghostscript(SimCase):
    CID = "ghostscript-125396"

    def test_absent_is_not_applicable(self):
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")

    def test_below_floor_is_affected(self):
        self.s.dpkg({"ghostscript": "10.07.0"})
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_10_08_0_is_info(self):
        self.s.dpkg({"ghostscript": "10.08.0"})
        self.assertEqual(results(self.s.check(self.CID)), ["info"])

    def test_debian_bookworm_patched_is_info(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"ghostscript": "10.0.0~dfsg-11+deb12u9"})
        self.assertEqual(results(self.s.check(self.CID)), ["info"])

    def test_debian_bookworm_unpatched_is_affected(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"ghostscript": "10.0.0~dfsg-11+deb12u8"})
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_debian_bookworm_trixie_stream_unpatched_is_affected(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"ghostscript": "10.05.1~dfsg-1"})
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_debian_unknown_stream_is_review(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"ghostscript": "9.56.1~dfsg-1"})
        self.assertEqual(results(self.s.check(self.CID)), ["review"])

    def test_libgs10_is_matched(self):
        self.s.dpkg({"libgs10": "10.07.0"})
        self.assertEqual(results(self.s.check(self.CID)), ["affected"])

    def test_libgssapi_krb5_is_not_ghostscript(self):
        self.s.write("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.s.dpkg({"libgssapi-krb5-2": "1.20.1-2+deb12u1"})
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")


class Idunno(SimCase):
    CID = "idunno-anticsrf-131914"

    def test_empty_is_pass(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check(self.CID), "PASS")

    def test_name_only_dll_is_review(self):
        body = b"Idunno.AntiCsrf synthetic fixture " + b"\x00" * 64
        self.s.write("~/sites/app/bin/Idunno.AntiCsrf.dll", body)
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_published_hash_match_is_affected(self):
        body = b"Idunno.AntiCsrf hash-match fixture " + b"\x01" * 32
        digest = hashlib.sha256(body).hexdigest()
        self.s.write("~/sites/app/bin/Idunno.AntiCsrf.dll", body)
        original = hc.IDUNNO_DLL_SHAS
        try:
            hc.IDUNNO_DLL_SHAS = frozenset(original) | {digest}
            c = self.s.check(self.CID)
        finally:
            hc.IDUNNO_DLL_SHAS = original
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_catalog_includes_published_official_sha(self):
        self.assertIn(IDUNNO_OFFICIAL_SHA, hc.IDUNNO_DLL_SHAS)
        self.assertEqual(len(hc.IDUNNO_DLL_SHAS), 3)

    def test_web_config_module_is_review(self):
        self.s.write("~/sites/app/Web.config",
                     '<?xml version="1.0"?>\n<configuration>\n'
                     '<system.webServer><modules>\n'
                     '<add name="AntiCsrfModule" type="Idunno.AntiCsrf.AntiCsrfModule, Idunno.AntiCsrf" />\n'
                     '</modules></system.webServer>\n</configuration>\n')
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_webconfig_cap_blocks_clean_pass(self):
        original = hc._IDUNNO_WEBCONFIG_CAP
        try:
            hc._IDUNNO_WEBCONFIG_CAP = 1
            self.s.write("~/sites/a/Web.config", "<configuration/>\n")
            self.s.write("~/sites/b/Web.config", "<configuration/>\n")
            c = self.s.check(self.CID)
            self.assertStatus(c, "BLOCKED")
            self.assertIn("Web.config", c["reason"])
            self.assertIn("incomplete", c["reason"].lower())
        finally:
            hc._IDUNNO_WEBCONFIG_CAP = original


if __name__ == "__main__":
    unittest.main()
