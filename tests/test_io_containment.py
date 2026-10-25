"""Deterministic I/O containment regressions: ancestor symlinks, swap races,
coverage gaps, binary review, host-override records and secret-safe rendering.
All fixtures are synthetic and live in temporary directories."""

import json
import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

import support
import check_public_package as cpp
import inventory
import render_report
import safeio

REAL_OPEN = os.open


def tmp():
    return Path(support.tmpdir())


def swap_on_open(trigger, swap):
    """Patch os.open so ``swap()`` runs once just before the matching open."""
    state = {"done": False}

    def fake(path, flags, *args, **kwargs):
        if not state["done"] and trigger(path, flags, kwargs):
            state["done"] = True
            swap()
        return REAL_OPEN(path, flags, *args, **kwargs)
    return mock.patch.object(os, "open", fake), state


class OutputContainment(unittest.TestCase):
    def setUp(self):
        self.d = tmp()
        (self.d / "outside" / "sub").mkdir(parents=True)
        os.symlink(self.d / "outside", self.d / "alias")

    def test_ancestor_symlink_refused_with_and_without_force(self):
        for force in (False, True):
            with self.assertRaises(OSError):
                safeio.safe_write(self.d / "alias" / "sub" / "forced.md", "SYNTHETIC", force=force)
        self.assertEqual(list((self.d / "outside" / "sub").iterdir()), [])

    def test_cli_outputs_refuse_ancestor_symlink(self):
        target = self.d / "alias" / "sub"
        for args in (["inventory.py", support.ROOT / "assets", "--out", target / "inv.json"],
                     ["render_report.py", support.ROOT / "assets/examples/baseline-report.json", "--out", target / "r.md"]):
            for extra in ([], ["--force"]):
                res = support.run_script(*(args + extra))
                self.assertEqual(res.returncode, 2, res.stderr)
        self.assertEqual(list((self.d / "outside" / "sub").iterdir()), [])

    def test_refusal_names_canonical_path_but_still_refuses(self):
        res = support.run_script("render_report.py", support.ROOT / "assets/examples/baseline-report.json",
                                 "--out", self.d / "alias" / "sub" / "r.md")
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("canonical path instead: %s" % (self.d / "outside" / "sub"), res.stderr)
        self.assertEqual(list((self.d / "outside" / "sub").iterdir()), [])

    def _portal(self):
        (self.d / "portal" / "sub").mkdir(parents=True)
        (self.d / "external" / "sub").mkdir(parents=True)

        def swap():
            os.rename(self.d / "portal", self.d / "portal.orig")
            os.symlink(self.d / "external", self.d / "portal")
        return swap

    def test_ancestor_swap_after_anchor_stays_inside(self):
        for force, trigger_name in ((True, ".tmp-"), (False, "result.md")):
            with self.subTest(force=force):
                self.d = tmp()
                swap = self._portal()
                patch, state = swap_on_open(lambda p, f, kw: kw.get("dir_fd") is not None
                                            and str(p).startswith(trigger_name), swap)
                with patch:
                    safeio.safe_write(self.d / "portal" / "sub" / "result.md", "SYNTHETIC-RACE", force=force)
                self.assertTrue(state["done"])
                self.assertFalse((self.d / "external" / "sub" / "result.md").exists())
                self.assertTrue((self.d / "portal.orig" / "sub" / "result.md").exists())

    def test_ancestor_swap_during_anchor_is_refused(self):
        swap = self._portal()
        patch, state = swap_on_open(lambda p, f, kw: p == "portal" and f & os.O_DIRECTORY, swap)
        with patch, self.assertRaises(OSError):
            safeio.safe_write(self.d / "portal" / "sub" / "result.md", "SYNTHETIC-RACE", force=True)
        self.assertTrue(state["done"])
        self.assertEqual(list((self.d / "external" / "sub").iterdir()), [])

    def test_unsupported_host_fails_explicitly(self):
        with mock.patch.object(os, "supports_dir_fd", set()):
            message = safeio.probe_host_support()
        self.assertIn("BLOCKED", message)
        with mock.patch.object(safeio, "HOST_SUPPORT_ERROR", message):
            with self.assertRaises(safeio.Unsupported):
                safeio.open_dir(self.d)
            self.assertEqual(inventory.main([str(self.d)]), 2)
            with self.assertRaises(safeio.Unsupported):
                safeio.safe_write(self.d / "x.md", "SYNTHETIC")


class TraversalContainment(unittest.TestCase):
    def setUp(self):
        self.d = tmp()
        self.root = self.d / "root"
        (self.root / "swap").mkdir(parents=True)
        (self.root / "swap" / "inside.txt").write_text("inside\n", encoding="utf-8")
        (self.root / "SKILL.md").write_text("x\n", encoding="utf-8")
        (self.d / "external").mkdir()
        (self.d / "external" / "composer.json").write_text("{}", encoding="utf-8")

    def _swap(self, to_symlink):
        def swap():
            os.rename(self.root / "swap", self.d / "swap.orig")
            if to_symlink:
                os.symlink(self.d / "external", self.root / "swap")
            else:
                os.rename(self.d / "external", self.root / "swap")
        return swap

    def test_inventory_detects_directory_swap(self):
        for to_symlink in (True, False):
            with self.subTest(to_symlink=to_symlink):
                self.setUp()
                patch, state = swap_on_open(lambda p, f, kw: p == "swap" and f & os.O_DIRECTORY, self._swap(to_symlink))
                inv = inventory.Inventory(str(self.root), inventory.DEFAULT_EXCLUDES, 1000, 10 ** 6)
                with patch:
                    inv.walk()
                doc = inv.result("fixture", None)
                self.assertTrue(state["done"])
                self.assertEqual(doc["manifests"], [])
                self.assertEqual(doc["coverage"]["status"], "PARTIAL")
                self.assertIn("changed_during_walk", doc["coverage"]["partial_reasons"])

    def test_package_scan_detects_directory_swap(self):
        patch, state = swap_on_open(lambda p, f, kw: p == "swap" and f & os.O_DIRECTORY, self._swap(True))
        with patch:
            rep = cpp.scan(self.root, [], cpp.DEFAULT_ALLOWED_HOSTS)
        self.assertTrue(state["done"])
        self.assertIn(("UNSCANNED", "swap"), {(i["code"], i["path"]) for i in rep.errors})


class CoverageGaps(unittest.TestCase):
    def setUp(self):
        self.root = tmp() / "repo"
        (self.root / ".git").mkdir(parents=True)
        (self.root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        (self.root / "opaque.bin").write_bytes(b"\x00SYNTHETIC")
        outside = tmp()
        os.symlink(outside, self.root / "linkdir")

    def test_strict_inventory_marks_gaps(self):
        res = support.run_script("inventory.py", self.root, "--strict")
        self.assertEqual(res.returncode, 3)
        cov = json.loads(res.stdout)["coverage"]
        self.assertEqual(cov["status"], "PARTIAL")
        self.assertEqual(cov["partial_reasons"], ["binary_not_scanned", "excluded_dir", "symlink_not_followed"])

    def test_explicit_accepted_exclusions_are_recorded(self):
        res = support.run_script("inventory.py", self.root, "--strict",
                                 "--accept-exclusion", ".git/=version-control metadata reviewed separately",
                                 "--accept-exclusion", "opaque.bin=synthetic binary reviewed by hand",
                                 "--accept-exclusion", "linkdir=symlink target is out of scope")
        self.assertEqual(res.returncode, 0, res.stderr)
        cov = json.loads(res.stdout)["coverage"]
        self.assertEqual(cov["status"], "COMPLETE_WITH_ACCEPTED_EXCLUSIONS")
        self.assertTrue(all(a["matched"] and a["reason"] for a in cov["accepted_exclusions"]))

    def test_exclusion_needs_reason(self):
        res = support.run_script("inventory.py", self.root, "--accept-exclusion", ".git/")
        self.assertEqual(res.returncode, 2)


class PackageReview(unittest.TestCase):
    def setUp(self):
        self.pkg = support.package_copy()

    def test_binary_needs_review_nonzero(self):
        (self.pkg / "screenshot.bin").write_bytes(b"\x00SYNTHETIC")
        res = support.run_script("check_public_package.py", self.pkg)
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertIn("NEEDS_REVIEW", res.stdout)
        self.assertNotIn("NO_RULE_MATCHED", res.stdout)

    def test_root_symlinks_are_not_canonicalized_silently(self):
        alias = tmp() / "root-alias"
        os.symlink(self.pkg, alias)
        for script, args in (("inventory.py", ("--strict",)), ("check_public_package.py", ("--json",))):
            result = support.run_script(script, alias, *args)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_host_policy_cannot_self_authorize_inside_package(self):
        policy = self.pkg / "host-policy.json"
        content = {"approved_by_role": "publication approver", "hosts": [
            {"host": "docs.vendor.example", "rationale": "synthetic public documentation exception"}]}
        policy.write_text(json.dumps(content), encoding="utf-8")
        result = support.run_script("check_public_package.py", self.pkg, "--host-policy", policy)
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside", result.stderr)
        outside = tmp() / "host-policy.json"
        content["approved_by_role"] = "model"
        outside.write_text(json.dumps(content), encoding="utf-8")
        result = support.run_script("check_public_package.py", self.pkg, "--host-policy", outside)
        self.assertEqual(result.returncode, 2)
        self.assertIn("machine", result.stderr)

    def test_host_override_is_recorded_not_silent(self):
        host = "docs." + "sample-vendor" + ".org"
        (self.pkg / "references" / "extra.md").write_text("See https://%s/guide\n" % host, encoding="utf-8")
        self.assertEqual(support.run_script("check_public_package.py", self.pkg).returncode, 1)
        policy = tmp() / "hosts.json"
        policy.write_text(json.dumps({"approved_by_role": "publication approver", "hosts": [
            {"host": host, "rationale": "public vendor documentation cited in references"}]}), encoding="utf-8")
        res = support.run_script("check_public_package.py", self.pkg, "--host-policy", policy, "--json")
        self.assertEqual(res.returncode, 3, res.stdout)
        out = json.loads(res.stdout)
        self.assertEqual(out["status"], "NEEDS_REVIEW")
        self.assertEqual(out["host_overrides"][0]["override_id"], "HOST-001")
        self.assertNotIn(host, res.stdout)
        self.assertGreaterEqual(out["matches_allowed_by_overrides"], 1)
        for bad in ({"approved_by_role": "x", "hosts": []},
                    {"approved_by_role": "publication approver", "hosts": [{"host": "*.x.org", "rationale": "wildcard is not exact"}]},
                    {"approved_by_role": "publication approver", "hosts": [{"host": host, "rationale": ""}]}):
            policy.write_text(json.dumps(bad), encoding="utf-8")
            self.assertEqual(support.run_script("check_public_package.py", self.pkg, "--host-policy", policy).returncode, 2)


    def test_policy_diagnostics_keep_rationale_and_host_local(self):
        host = "docs." + "synthetic-review-public" + ".org"
        token = "ghp_" + "a1" * 18
        (self.pkg / "README.md").write_text("Reference https://" + host + "/guide\n")
        policy = tmp() / "policy.json"
        policy.write_text(json.dumps({
            "approved_by_role": "publication approver",
            "hosts": [{"host": host, "rationale": "Synthetic marker " + token}]
        }))
        for flags in ((), ("--json",)):
            result = support.run_script("check_public_package.py", self.pkg, "--host-policy", policy, *flags)
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertNotIn(host, result.stdout + result.stderr)
        doc = support.load_example("baseline")
        path = tmp() / "report.json"
        path.write_text(json.dumps(doc))
        result = support.run_script("validate_report.py", path, "--public", "--host-policy", policy, "--json")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn(host, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["public_scan"], "needs_review")


class SecretSafeRendering(unittest.TestCase):
    # Secret-shaped fixtures are assembled at runtime so this file passes the
    # package's own self-check.
    BEGIN, END, AT = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----", "@"
    PEM = BEGIN + "\nSYNTHETIC-PEM-BODY-NOT-A-KEY-12345\n" + END

    def test_inline_text_redacts_userinfo_and_whole_pem(self):
        for userinfo in ("fixture-user:pw", "fixture-user:", "fixture-user"):
            url = "https://" + userinfo + self.AT + "h.invalid/a"
            self.assertNotIn("fixture-user", render_report.t(url))
        out = render_report.t("before " + self.PEM + " after")
        self.assertNotIn("SYNTHETIC-PEM-BODY", out)
        self.assertNotIn("END PRIVATE KEY", out)
        self.assertNotIn("SYNTHETIC-PEM-BODY", render_report.t(self.BEGIN + "\nSYNTHETIC-PEM-BODY-NOT-A-KEY"))

    def test_render_refuses_secret_reports_even_with_allow_invalid(self):
        doc = support.load_example("baseline")
        doc["sources"][0]["url"] = "https://" + "fixture-user:pw" + self.AT + "h.invalid/advisory"
        doc["evidence"][0]["summary"] = "key material " + self.PEM
        d = tmp()
        (d / "r.json").write_text(json.dumps(doc), encoding="utf-8")
        for extra in ([], ["--allow-invalid"]):
            res = support.run_script("render_report.py", d / "r.json", "--out", d / "r.md", *extra)
            self.assertEqual(res.returncode, 1)
            self.assertFalse((d / "r.md").exists())
            self.assertNotIn("SYNTHETIC-PEM-BODY", res.stdout + res.stderr)
            self.assertNotIn("fixture-user", res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
