"""Fixture tests for the 24 Nov 2026 8 PM security watch.

Synthetic hosts only. Never starts PHP, ionCube, WHMCS, vpxd or any audited
program. No PoC payloads, no personal data, no network. Never asserts against
configuration.php contents (that file holds secrets on real installs).
"""

import json
import os
import unittest
from unittest import mock

import hostfix
import host_checks as hc
import hostscan as hs

results = hostfix.results

NEW_IDS = ("whmcs-82981",)


def whmcs_version_php(version, include_marker=True):
    """Synthetic ionCube-style header with a plaintext Version line."""
    lines = ["<?php //ICB0 56:0"]
    if include_marker:
        lines.extend([
            "// *************************************************************************",
            "// *                                                                       *",
            "// * WHMCS - The Complete Client Management, Billing & Support Solution    *",
            "// * Copyright (c) WHMCS Ltd. All Rights Reserved,                         *",
            "// * Version: %s (%s-release.1)                                      *" % (version, version),
            "// *                                                                       *",
            "// *************************************************************************",
        ])
    else:
        lines.append("// * Version: %s *" % version)
    lines.append("// binary payload placeholder")
    return "\n".join(lines) + "\n"


def whmcs_assign_php(version):
    return "<?php\n// WHMCS version file (synthetic)\n$whmcsversion = '%s';\n" % version


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

    def install_whmcs(self, version, root="~/www/billing", style="header"):
        self.s.write(root + "/configuration.php", "<?php\n# synthetic; never read by the check\n")
        body = whmcs_version_php(version) if style == "header" else whmcs_assign_php(version)
        self.s.write(root + "/includes/version.php", body)
        return root


class Catalog(SimCase):
    def test_new_ids_and_count(self):
        self.assertEqual(len(hc.CHECK_IDS), 88)
        self.assertEqual(len(hc.CHECK_IDS), len(set(hc.CHECK_IDS)))
        for cid in NEW_IDS:
            self.assertIn(cid, hc.CHECK_IDS)
            self.assertNotIn(cid, hc.INDICATOR_CHECKS)
            meta = next(m for m in hc.CHECKS if m["id"] == cid)
            self.assertTrue(meta["sources"], cid)
            for key in meta["sources"]:
                self.assertIn(key, hc.SRC)
                self.assertTrue(hc.SRC[key][1].startswith("https://"), key)

    def test_skipped_rows_name_evening_items(self):
        blob = " ".join("%s %s" % kv for kv in hc.SKIPPED)
        self.assertIn("VMSA-2026-0011", blob)
        self.assertIn("CVE-2026-123903", blob)
        self.assertIn("PlayStation", blob)
        self.assertIn("McDonald", blob)
        self.assertIn("Hugendubel", blob)
        self.assertIn("Tolino", blob)
        self.assertIn("eBook" + ".de", blob)
        self.assertIn("Rackspace Spot", blob)
        self.assertIn("8 Dec", blob)
        self.assertIn("Elecbrakes", blob)

    def test_reviewed_hosts_include_whmcs(self):
        import textscan
        for host in ("help.whmcs.com", "blog.whmcs.com", "docs.whmcs.com"):
            self.assertIn(host, textscan.REVIEWED_PUBLIC_HOSTS)


class Whmcs82981(SimCase):
    CID = "whmcs-82981"

    def test_absent_is_not_applicable(self):
        for platform in ("darwin", "linux", "windows"):
            self.assertStatus(self.sim(platform).check(self.CID), "NOT_APPLICABLE")

    def test_9_0_9_is_affected(self):
        self.install_whmcs("9.0.9")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_9_1_1_is_affected(self):
        self.install_whmcs("9.1.1")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_9_0_10_is_info(self):
        self.install_whmcs("9.0.10")
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_9_1_2_is_info(self):
        self.install_whmcs("9.1.2")
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])

    def test_8_13_7_is_info_out_of_cve_range(self):
        # CVE-2026-82981 starts at 9.0.0; 8.13 is not in range.
        self.install_whmcs("8.13.7")
        c = self.s.check(self.CID)
        self.assertStatus(c, "PASS")
        self.assertEqual(results(c), ["info"])
        detail = " ".join(f.get("detail", "") for f in c.get("findings", []))
        self.assertIn("9.0.0", detail)

    def test_assign_form_9_0_9_is_affected(self):
        self.install_whmcs("9.0.9", style="assign")
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])

    def test_missing_configuration_php_is_not_whmcs(self):
        self.s.write("~/www/billing/includes/version.php", whmcs_version_php("9.0.9"))
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")

    def test_version_without_whmcs_marker_is_not_whmcs(self):
        self.s.write("~/www/billing/configuration.php", "<?php\n")
        self.s.write("~/www/billing/includes/version.php", whmcs_version_php("9.0.9", include_marker=False))
        self.assertStatus(self.s.check(self.CID), "NOT_APPLICABLE")

    def test_unreadable_version_is_blocked_unknown(self):
        root = self.install_whmcs("9.0.9")
        path = self.s.path(root + "/includes/version.php")
        os.chmod(path, 0)
        self.addCleanup(lambda: os.chmod(path, 0o644))
        c = self.s.check(self.CID)
        self.assertIn(c["status"], ("BLOCKED", "FAIL"))
        kinds = results(c)
        self.assertTrue("unknown" in kinds or "affected" in kinds, kinds)

    def test_never_reads_configuration_php(self):
        # Poison configuration.php with a parseable fake version; the check must
        # ignore it and use includes/version.php only. Also spy reads so opening
        # configuration.php (even and discarding) fails the test.
        root = "~/www/billing"
        self.s.write(root + "/configuration.php",
                     "<?php\n$whmcsversion = '9.0.10';\n# Version: 9.0.10\n")
        self.s.write(root + "/includes/version.php", whmcs_version_php("9.0.9"))
        orig_text, orig_bytes = hs.read_text, hs.read_bytes

        def guard_text(path, *a, **k):
            self.assertNotIn("configuration.php", str(path).replace("\\", "/"),
                             "must not open configuration.php")
            return orig_text(path, *a, **k)

        def guard_bytes(path, *a, **k):
            self.assertNotIn("configuration.php", str(path).replace("\\", "/"),
                             "must not open configuration.php")
            return orig_bytes(path, *a, **k)

        with mock.patch.object(hs, "read_text", side_effect=guard_text), \
                mock.patch.object(hs, "read_bytes", side_effect=guard_bytes):
            c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])
        for f in c.get("findings", []):
            path = (f.get("path") or "").replace("\\", "/")
            self.assertNotIn("configuration.php", path)

    def test_prerelease_of_floor_is_affected(self):
        self.install_whmcs("9.0.10-beta.1")
        # Header embeds the raw string; re-write with beta in Version line.
        self.s.write("~/www/billing/includes/version.php",
                     whmcs_version_php("9.0.10").replace("9.0.10", "9.0.10-beta.1"))
        c = self.s.check(self.CID)
        self.assertStatus(c, "FAIL")
        self.assertEqual(results(c), ["affected"])


if __name__ == "__main__":
    unittest.main()
