"""Fixture tests for the 20 Nov 2026 host-check watch.

Synthetic hosts only. Nothing here executes openssl, gpustack, VMware Tools,
ASUS Control Center Express, python or any audited program. No PoC payloads,
no credential values, no network, no hard-coded keys.
"""

import json
import os
import unittest

import hostfix
import host_checks as hc

results = hostfix.results
dotted = hostfix.dotted


def _openssl_banner(ver):
    return b"\x7fELF" + b"\x00" * 64 + ("OpenSSL %s" % ver).encode("ascii") + b"\x00" * 32


def _opensslv_h(ver):
    return '# define OPENSSL_VERSION_STR "%s"\n# define OPENSSL_VERSION_TEXT "OpenSSL %s 1 Jan 2026"\n' % (ver, ver)


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
        self.assertEqual(len(hc.CHECK_IDS), 80)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        for cid in ("openssl-121481", "gpustack-102895", "vmware-tools-123894", "asus-acce-114202"):
            self.assertIn(cid, hc.CHECK_IDS)
            self.assertNotIn(cid, hc.INDICATOR_CHECKS)
        openssl = next(m for m in hc.CHECKS if m["id"] == "openssl-121481")
        gpu = next(m for m in hc.CHECKS if m["id"] == "gpustack-102895")
        tools = next(m for m in hc.CHECKS if m["id"] == "vmware-tools-123894")
        asus = next(m for m in hc.CHECKS if m["id"] == "asus-acce-114202")
        self.assertTrue(openssl["uses_walk"])
        self.assertTrue(gpu["uses_walk"])
        self.assertFalse(tools["uses_walk"])
        self.assertFalse(asus["uses_walk"])
        for m in (openssl, gpu, tools, asus):
            self.assertTrue(m["sources"], m["id"])
            for key in m["sources"]:
                self.assertIn(key, hc.SRC)
                self.assertTrue(hc.SRC[key][1].startswith("https://"), key)
        php = next(m for m in hc.CHECKS if m["id"] == "php-129289")
        self.assertIn("ghsa-gr4f", php["sources"])

    def test_skipped_rows_name_non_host_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("GHSA-gr4f-wgx5-jpfv", blob)
        self.assertIn("CVE-2026-123890", blob)
        self.assertIn("SDDC Manager", blob)
        self.assertIn("ICSA-26-323-01", blob)
        self.assertIn("OpenPLC", blob)
        self.assertIn("Elecbrakes", blob)
        self.assertIn("libumqtt", blob)
        self.assertIn("Rakuten Securities", blob)
        self.assertIn("Prime Intellect", blob)
        self.assertIn("SBC Medical", blob)
        self.assertIn("BundID", blob)
        self.assertIn("Equinor", blob)
        self.assertIn("KPMG Canada", blob)
        self.assertIn("JPMorgan", blob)

    def test_never_starts_named_binaries(self):
        doc = hc.__doc__
        self.assertIn("openssl", doc)
        self.assertIn("gpustack", doc)
        self.assertIn("VMware Tools", doc)
        self.assertIn("Control Center Express", doc)

    def test_floors_are_not_ipv4_literals(self):
        with open(hc.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn(dotted(13, 1, 5, 0), src)


class OpenSsl121481(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("openssl-121481"), "NOT_APPLICABLE")

    def test_openssl_3_is_info(self):
        self.s.dpkg({"libssl3": "3.0.13-0ubuntu3"})
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])
        self.assertIn("3.x", c["findings"][0]["detail"])

    def test_libssl3t64_is_info(self):
        self.s.dpkg({"libssl3t64": "3.5.3-1"})
        self.assertEqual(results(self.s.check("openssl-121481")), ["info"])

    def test_openssl_403_is_affected(self):
        self.s.dpkg({"openssl": "4.0.3"})
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "4.0.3")

    def test_openssl_404_is_info(self):
        self.s.dpkg({"openssl": "4.0.4"})
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_openssl_410_is_affected(self):
        self.s.dpkg({"libssl4": "4.1.0"})
        self.assertEqual(results(self.s.check("openssl-121481")), ["affected"])

    def test_openssl_411_is_info(self):
        self.s.dpkg({"openssl": "4.1.1"})
        self.assertEqual(results(self.s.check("openssl-121481")), ["info"])

    def test_prerelease_of_40_floor_is_affected(self):
        self.s.dpkg({"openssl": "4.0.4rc1"})
        c = self.s.check("openssl-121481")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("prerelease", c["findings"][0]["detail"])

    def test_prerelease_of_41_floor_is_affected(self):
        self.s.dpkg({"openssl": "4.1.1rc1"})
        self.assertEqual(results(self.s.check("openssl-121481")), ["affected"])

    def test_42_is_info(self):
        self.s.dpkg({"openssl": "4.2.0"})
        self.assertEqual(results(self.s.check("openssl-121481")), ["info"])

    def test_dev_package_is_skipped(self):
        self.s.dpkg({"libssl-dev": "4.0.3", "openssl-doc": "4.0.3"})
        self.assertStatus(self.s.check("openssl-121481"), "NOT_APPLICABLE")

    def test_backport_note(self):
        self.s.dpkg({"openssl": "4.0.3-1ubuntu1"})
        c = self.s.check("openssl-121481")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("backport", c["findings"][0]["detail"])

    def test_cellar_formula(self):
        m = self.sim("darwin")
        m.mkdir("/opt/homebrew/Cellar/openssl@4/4.0.3")
        c = m.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_cellar_3_is_info(self):
        m = self.sim("darwin")
        m.mkdir("/opt/homebrew/Cellar/openssl@3/3.5.4")
        self.assertEqual(results(m.check("openssl-121481")), ["info"])

    def test_header_version(self):
        self.s.write("/usr/include/openssl/opensslv.h", _opensslv_h("4.0.3"))
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "4.0.3")

    def test_whitespace_header_is_unknown(self):
        self.s.write("/usr/include/openssl/opensslv.h",
                     '# define OPENSSL_VERSION_STR "   "\n')
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])
        self.assertNotIn("check error", c["reason"])

    def test_whitespace_header_does_not_abort_binary_scan(self):
        self.s.write("/usr/include/openssl/opensslv.h",
                     '# define OPENSSL_VERSION_STR "   "\n')
        self.s.write("/usr/bin/openssl", _openssl_banner("4.0.3"))
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertIn("unknown", results(c))
        self.assertIn("affected", results(c))
        self.assertNotIn("check error", c["reason"])

    def test_binary_banner_not_executed(self):
        self.s.write("/usr/bin/openssl", _openssl_banner("4.0.3"))
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "4.0.3")

    def test_binary_banner_dev_of_40_floor_is_affected(self):
        self.s.write("/usr/bin/openssl", _openssl_banner("4.0.4-dev"))
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "4.0.4-dev")
        self.assertIn("prerelease", c["findings"][0]["detail"])

    def test_binary_banner_dev_of_41_floor_is_affected(self):
        self.s.write("/usr/bin/openssl", _openssl_banner("4.1.1-dev"))
        c = self.s.check("openssl-121481")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], "4.1.1-dev")

    def test_binary_banner_floor_release_is_info(self):
        self.s.write("/usr/bin/openssl", _openssl_banner("4.0.4"))
        self.assertEqual(results(self.s.check("openssl-121481")), ["info"])

    def test_libressl_is_info(self):
        self.s.write("/usr/bin/openssl",
                     b"\x7fELF" + b"\x00" * 64 + b"LibreSSL 3.9.2" + b"\x00" * 32)
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])
        self.assertIn("LibreSSL", c["findings"][0]["detail"])

    def test_unversioned_binary_is_unknown(self):
        self.s.write("/usr/bin/openssl", b"\x7fELF" + b"\x00" * 128)
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_image_patch_level(self):
        self.s.write("~/code/web/Dockerfile", "FROM openssl:4.0.3\n")
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_image_floor(self):
        self.s.write("~/code/web/Dockerfile", "FROM openssl:4.0.4\n")
        self.assertEqual(results(self.s.check("openssl-121481")), ["info"])

    def test_moving_tag_is_unknown(self):
        self.s.write("~/code/web/Dockerfile", "FROM openssl:latest\n")
        c = self.s.check("openssl-121481")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_digest_pinned_is_unknown(self):
        self.s.write("~/code/web/Dockerfile",
                     "FROM openssl:4.0.4@sha256:%s\n" % ("a" * 64))
        self.assertEqual(results(self.s.check("openssl-121481")), ["unknown"])

    def test_windows_registry(self):
        w = self.sim("windows")
        c = w.check("openssl-121481", registry=[{"name": "OpenSSL 4.0.3 (64-bit)", "version": "4.0.3"}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_pe_version(self):
        w = self.sim("windows")
        w.write("C:/Program Files/OpenSSL-Win64/bin/openssl.exe",
                hostfix.pe_with_version(dotted(4, 0, 3, 0)))
        c = w.check("openssl-121481")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])


class GpuStack102895(SimCase):
    def test_absent_is_not_applicable(self):
        for platform in ("linux", "darwin", "windows"):
            self.assertStatus(self.sim(platform).check("gpustack-102895"), "NOT_APPLICABLE")

    def test_below_floor_is_affected(self):
        self.s.venv("~/venvs/gpu", {"gpustack": "2.1.0"})
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_just_below_floor_is_affected(self):
        self.s.venv("~/venvs/gpu", {"gpustack": "2.1.9"})
        self.assertEqual(results(self.s.check("gpustack-102895")), ["affected"])

    def test_floor_is_info(self):
        self.s.venv("~/venvs/gpu", {"gpustack": "2.2.0"})
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_prerelease_of_floor_is_affected(self):
        self.s.venv("~/venvs/gpu", {"gpustack": "2.2.0rc1"})
        self.assertEqual(results(self.s.check("gpustack-102895")), ["affected"])

    def test_exact_pin_below_floor(self):
        self.s.write("~/code/app/requirements.txt", "gpustack==2.1.2\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_exact_pin_at_floor(self):
        self.s.write("~/code/app/requirements.txt", "gpustack==2.2.0\n")
        self.assertEqual(results(self.s.check("gpustack-102895")), ["info"])

    def test_arbitrary_equality_pin(self):
        self.s.write("~/code/app/requirements.txt", "gpustack===2.1.0\n")
        self.assertEqual(results(self.s.check("gpustack-102895")), ["affected"])

    def test_unpinned_spec_is_review(self):
        self.s.write("~/code/app/requirements.txt", "gpustack>=2.0\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_image_below_floor(self):
        self.s.write("~/code/app/Dockerfile", "FROM registry.example.com/gpustack:2.1.0\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_short_from_name_is_not_a_pip_pin(self):
        self.s.write("~/code/app/Dockerfile", "FROM gpustack/gpustack:2.2.0\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_dockerfile_pip_pin(self):
        self.s.write("~/code/app/Dockerfile", "RUN pip install gpustack==2.1.0\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_dockerfile_unpinned_pip_is_review(self):
        self.s.write("~/code/app/Dockerfile", "RUN pip install gpustack>=2.0\n")
        c = self.s.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["review"])

    def test_from_image_does_not_drop_run_pip_review(self):
        self.s.write("~/code/app/Dockerfile",
                     "FROM gpustack/gpustack:2.2.0\nRUN pip install gpustack>=2.0\n")
        kinds = results(self.s.check("gpustack-102895"))
        self.assertIn("info", kinds)
        self.assertIn("review", kinds)

    def test_moving_tag_is_unknown(self):
        self.s.write("~/code/app/Dockerfile", "FROM registry.example.com/gpustack:latest\n")
        self.assertEqual(results(self.s.check("gpustack-102895")), ["unknown"])

    def test_windows_venv(self):
        w = self.sim("windows")
        w.venv("~/venvs/gpu", {"gpustack": "2.1.0"}, windows_layout=True)
        c = w.check("gpustack-102895")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])


class VmwareTools123894(SimCase):
    def test_linux_absent_is_not_applicable(self):
        self.assertStatus(self.s.check("vmware-tools-123894"), "NOT_APPLICABLE")

    def test_open_vm_tools_is_not_this_cve(self):
        self.s.dpkg({"open-vm-tools": "12.5.0-1"})
        self.assertStatus(self.s.check("vmware-tools-123894"), "NOT_APPLICABLE")

    def test_windows_13_below_floor_is_affected(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894",
                    registry=[{"name": "VMware Tools", "version": dotted(13, 1, 4, 0)}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_13_floor_is_info(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894",
                    registry=[{"name": "VMware Tools", "version": dotted(13, 1, 5, 0)}])
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_windows_1254_is_affected(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "12.5.4"}])
        self.assertEqual(results(c), ["affected"])

    def test_windows_1255_is_info(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "12.5.5"}])
        self.assertEqual(results(c), ["info"])

    def test_windows_12410_without_arch_is_affected(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "12.4.10"}])
        self.assertEqual(results(c), ["affected"])
        self.assertIn("32-bit", c["findings"][0]["detail"])

    def test_windows_12410_32bit_registry_is_info(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894",
                    registry=[{"name": "VMware Tools", "version": "12.4.10",
                               "key": r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"}])
        self.assertEqual(results(c), ["info"])

    def test_windows_1249_is_affected(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "12.4.9"}])
        self.assertEqual(results(c), ["affected"])

    def test_windows_11_is_affected(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "11.3.5"}])
        self.assertEqual(results(c), ["affected"])

    def test_windows_14_is_info(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": "14.0.0"}])
        self.assertEqual(results(c), ["info"])

    def test_empty_registry_version_is_unknown(self):
        w = self.sim("windows")
        c = w.check("vmware-tools-123894", registry=[{"name": "VMware Tools", "version": ""}])
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_program_files_pe(self):
        w = self.sim("windows")
        w.write("C:/Program Files/VMware/VMware Tools/vmtoolsd.exe",
                hostfix.pe_with_version(dotted(13, 1, 4, 0)))
        c = w.check("vmware-tools-123894")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_12410_32bit_pe_is_info(self):
        w = self.sim("windows")
        w.write("C:/Program Files (x86)/VMware/VMware Tools/vmtoolsd.exe",
                hostfix.pe_with_version(dotted(12, 4, 10, 0), machine=0x14C))
        self.assertEqual(results(w.check("vmware-tools-123894")), ["info"])

    def test_windows_12410_64bit_pe_is_affected(self):
        w = self.sim("windows")
        w.write("C:/Program Files/VMware/VMware Tools/vmtoolsd.exe",
                hostfix.pe_with_version(dotted(12, 4, 10, 0), machine=0x8664))
        c = w.check("vmware-tools-123894")
        self.assertEqual(results(c), ["affected"])
        self.assertIn("32-bit", c["findings"][0]["detail"])

    def test_windows_12410_native_32bit_pe_reconciles_registry(self):
        w = self.sim("windows")
        w.write("C:/Program Files/VMware/VMware Tools/vmtoolsd.exe",
                hostfix.pe_with_version(dotted(12, 4, 10, 0), machine=0x14C))
        c = w.check("vmware-tools-123894",
                    registry=[{"name": "VMware Tools", "version": "12.4.10"}])
        self.assertStatus(c, "PASS")
        self.assertEqual(set(results(c)), {"info"})
        self.assertNotIn("check error", c["reason"])

    def test_windows_12410_64bit_pe_keeps_registry_affected(self):
        w = self.sim("windows")
        w.write("C:/Program Files/VMware/VMware Tools/vmtoolsd.exe",
                hostfix.pe_with_version(dotted(12, 4, 10, 0), machine=0x8664))
        c = w.check("vmware-tools-123894",
                    registry=[{"name": "VMware Tools", "version": "12.4.10"}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(set(results(c)), {"affected"})


class AsusAcce114202(SimCase):
    def test_linux_absent_is_not_applicable(self):
        self.assertStatus(self.s.check("asus-acce-114202"), "NOT_APPLICABLE")

    def test_windows_below_floor_is_affected(self):
        w = self.sim("windows")
        c = w.check("asus-acce-114202",
                    registry=[{"name": "ASUS Control Center Express", "version": "1.7.27"}])
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_windows_128_is_affected(self):
        w = self.sim("windows")
        c = w.check("asus-acce-114202",
                    registry=[{"name": "ASUS Control Center Express", "version": "1.7.28"}])
        self.assertEqual(results(c), ["affected"])

    def test_windows_floor_is_info(self):
        w = self.sim("windows")
        c = w.check("asus-acce-114202",
                    registry=[{"name": "ASUS Control Center Express", "version": "1.7.29"}])
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_enterprise_without_express_is_not_this_check(self):
        w = self.sim("windows")
        c = w.check("asus-acce-114202",
                    registry=[{"name": "ASUS Control Center", "version": "3.0.0"}])
        self.assertStatus(c, "NOT_APPLICABLE")

    def test_empty_version_is_unknown(self):
        w = self.sim("windows")
        c = w.check("asus-acce-114202",
                    registry=[{"name": "ASUS Control Center Express", "version": ""}])
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])

    def test_program_files_pe(self):
        w = self.sim("windows")
        w.write("C:/Program Files/ASUS/Control Center Express/ACCE.exe",
                hostfix.pe_with_version(dotted(1, 7, 27, 0)))
        c = w.check("asus-acce-114202")
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_unrelated_exe_is_not_the_product_version(self):
        w = self.sim("windows")
        w.write("C:/Program Files/ASUS/Control Center Express/AAA.exe",
                hostfix.pe_with_version(dotted(9, 0, 0, 0)))
        w.write("C:/Program Files/ASUS/Control Center Express/ACCE.exe",
                hostfix.pe_with_version(dotted(1, 7, 27, 0)))
        c = w.check("asus-acce-114202")
        self.assertEqual(results(c), ["affected"])
        self.assertEqual(c["findings"][0]["version"], dotted(1, 7, 27, 0))

    def test_unrelated_exe_only_is_unknown(self):
        w = self.sim("windows")
        w.write("C:/Program Files/ASUS/Control Center Express/Setup.exe",
                hostfix.pe_with_version(dotted(9, 0, 0, 0)))
        c = w.check("asus-acce-114202")
        self.assertStatus(c, "BLOCKED")
        self.assertEqual(results(c), ["unknown"])


if __name__ == "__main__":
    unittest.main()
