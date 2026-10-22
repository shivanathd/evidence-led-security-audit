import json
import os
import re
import stat
import unittest
from pathlib import Path

import support
import render_report
import validate_report as vr

HOSTILE = ("<script>alert(1)</script> [click](javascript:void) `rm -rf` | col \x1b[31mred\x1b[0m "
           "\u202eevil\u202c $(touch pwned) ![img](x)")


class Rendering(unittest.TestCase):
    def render(self, doc, base=None):
        return render_report.render(doc, vr.validate(doc, base))

    def test_deterministic(self):
        doc = support.load_example("baseline")
        self.assertEqual(self.render(doc), self.render(json.loads(json.dumps(doc))))

    def test_hostile_text_is_neutralized(self):
        doc = support.apply_ops(support.load_example("baseline"), [
            {"op": "set", "path": "evidence[id=EV-006].summary", "value": HOSTILE},
            {"op": "set", "path": "findings[id=F-003].title", "value": HOSTILE}])
        md = self.render(doc)
        self.assertNotIn("<script>", md)
        self.assertIsNone(re.search(r"(?<!\\)\]\(javascript", md), "live link survived")
        self.assertNotIn("\x1b", md)
        self.assertNotIn("\u202e", md)
        self.assertIsNone(re.search(r"(?<!\\)\| col", md), "unescaped table pipe survived")
        self.assertIn("&lt;script&gt;", md)
        self.assertFalse(Path("pwned").exists())

    def test_secret_shaped_text_redacted(self):
        doc = support.load_example("baseline")
        doc["findings"][0]["notes"] = "see " + support.PLACEHOLDERS["{{FAKE_AWS_KEY}}"]
        md = render_report.render(doc, [])
        self.assertNotIn(support.PLACEHOLDERS["{{FAKE_AWS_KEY}}"], md)
        self.assertIn("REDACTED", md)

    def test_baseline_and_after_fix_render_separately(self):
        b = self.render(support.load_example("baseline"))
        a = self.render(support.load_example("after_fix"), support.load_example("baseline"))
        self.assertIn("# Baseline security audit report", b)
        self.assertIn("# After-fix retest report", a)
        self.assertIn("## Fix and retest plan", b)
        self.assertIn("vendor patch evidence; no exploit reproduction", a)
        self.assertIn("CHK-07 **BLOCKED**", a)

    def test_after_fix_render_requires_baseline(self):
        res = support.run_script("render_report.py", support.EXAMPLES / "after-fix-report.json")
        self.assertEqual(res.returncode, 1)
        self.assertIn("BASELINE_REQUIRED", res.stderr)

    def test_invalid_report_refused_or_bannered(self):
        doc = support.apply_ops(support.load_example("baseline"), [
            {"op": "set", "path": "verdict.overall", "value": "CLEAR_WITHIN_COVERED_SCOPE"}])
        d = Path(support.tmpdir())
        p = d / "bad.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        res = support.run_script("render_report.py", p)
        self.assertEqual(res.returncode, 1)
        self.assertEqual(res.stdout, "")
        res = support.run_script("render_report.py", p, "--allow-invalid")
        self.assertEqual(res.returncode, 1)
        self.assertIn("STRUCTURE INVALID", res.stdout)


class OutputSafety(unittest.TestCase):
    def setUp(self):
        self.d = Path(support.tmpdir())
        self.src = support.EXAMPLES / "baseline-report.json"

    def test_no_overwrite_without_force(self):
        out = self.d / "r.md"
        out.write_text("keep", encoding="utf-8")
        res = support.run_script("render_report.py", self.src, "--out", out)
        self.assertEqual(res.returncode, 2)
        self.assertEqual(out.read_text(encoding="utf-8"), "keep")
        res = support.run_script("render_report.py", self.src, "--out", out, "--force")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("# Baseline", out.read_text(encoding="utf-8"))

    def test_refuses_symlink_even_with_force(self):
        victim = self.d / "victim.txt"
        victim.write_text("original", encoding="utf-8")
        link = self.d / "link.md"
        os.symlink(victim, link)
        for extra in ([], ["--force"]):
            res = support.run_script("render_report.py", self.src, "--out", link, *extra)
            self.assertEqual(res.returncode, 2)
        self.assertEqual(victim.read_text(encoding="utf-8"), "original")

    def test_output_mode_is_private(self):
        out = self.d / "new.md"
        res = support.run_script("render_report.py", self.src, "--out", out)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode) & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
