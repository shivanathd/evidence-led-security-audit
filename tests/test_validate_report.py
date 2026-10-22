import json
import tempfile
import unittest
from pathlib import Path

import support
import textscan
import validate_report as vr


def codes(issues):
    return {i.code for i in issues if i.level == "ERROR"}


class SampleReports(unittest.TestCase):
    def test_baseline_sample_is_structurally_valid(self):
        self.assertEqual(codes(vr.validate(support.load_example("baseline"), public=True)), set())

    def test_after_fix_sample_is_valid_against_baseline(self):
        issues = vr.validate(support.load_example("after_fix"), support.load_example("baseline"), public=True)
        self.assertEqual(codes(issues), set())

    def test_samples_stay_incomplete_while_checks_are_blocked(self):
        for kind in ("baseline", "after_fix"):
            self.assertEqual(vr.expected_verdict(support.load_example(kind)), "INCOMPLETE")


class AdversarialCorpus(unittest.TestCase):
    """Each synthetic case must be rejected with its listed error codes."""

    def test_corpus_cases(self):
        corpus = json.loads(support.CORPUS.read_text(encoding="utf-8"))["cases"]
        self.assertGreaterEqual(len(corpus), 30)
        baseline = support.load_example("baseline")
        for case in corpus:
            with self.subTest(case=case["name"]):
                doc = support.apply_ops(support.load_example(case["base"]), case["ops"])
                issues = vr.validate(doc, baseline if case["compare_baseline"] else None)
                found = codes(issues)
                self.assertTrue(found, "case %s produced no errors" % case["name"])
                for code in case["expect_codes"]:
                    self.assertIn(code, found, "case %s missing %s; got %s" % (case["name"], code, sorted(found)))

    def test_clear_control_is_valid(self):
        """The CLEAR mutation used by several cases is itself valid, so those cases fail for their own reason."""
        doc = support.apply_ops(support.load_example("after_fix"), CLEAR_OPS)
        self.assertEqual(codes(vr.validate(doc, support.load_example("baseline"))), set())
        self.assertEqual(vr.expected_verdict(doc), "CLEAR_WITHIN_COVERED_SCOPE")


CLEAR_OPS = [
    {"op": "set", "path": "evidence[id=EV-151].collection_status", "value": "complete"},
    {"op": "set", "path": "required_checks[id=CHK-07].status", "value": "PASS"},
    {"op": "delete", "path": "required_checks[id=CHK-07].reason"},
    {"op": "set", "path": "verdict.overall", "value": "CLEAR_WITHIN_COVERED_SCOPE"},
]


class BaselineContract(unittest.TestCase):
    def setUp(self):
        self.after = support.load_example("after_fix")
        self.base = support.load_example("baseline")

    def test_missing_scalar_or_invalid_baseline_is_an_error(self):
        self.assertIn("BASELINE_REQUIRED", codes(vr.validate(self.after)))
        self.assertIn("BASELINE_INVALID", codes(vr.validate(self.after, 5)))
        bad = support.apply_ops(self.base, [{"op": "set", "path": "verdict.overall", "value": "CLEAR_WITHIN_COVERED_SCOPE"}])
        self.assertIn("BASELINE_INVALID", codes(vr.validate(self.after, bad)))
        self.assertIn("BASELINE_MISMATCH", codes(vr.validate(self.after, self.after)))

    def test_cli_rejects_missing_or_scalar_baseline(self):
        res = support.run_script("validate_report.py", support.EXAMPLES / "after-fix-report.json")
        self.assertEqual(res.returncode, 1)
        self.assertIn("BASELINE_REQUIRED", res.stdout)
        d = Path(support.tmpdir())
        (d / "b.json").write_text("5", encoding="utf-8")
        res = support.run_script("validate_report.py", support.EXAMPLES / "after-fix-report.json", "--baseline", d / "b.json")
        self.assertEqual(res.returncode, 2)


class PublicScan(unittest.TestCase):
    def setUp(self):
        self.host = "advisories." + "corp-private" + ".com"
        self.doc = support.apply_ops(support.load_example("baseline"), [
            {"op": "append", "path": "sources", "value": {
                "id": "SRC-X", "title": "Private advisory", "url": "https://" + self.host + "/a",
                "retrieved_on": "2026-10-22", "kind": "other"}},
            {"op": "append", "path": "coverage_notes", "value": "Mirror at " + self.host + " was not reachable."}])

    def test_sources_do_not_self_allowlist_and_host_is_withheld(self):
        issues = vr.validate(self.doc, public=True)
        leaks = [i for i in issues if i.code == "PUBLIC_LEAK"]
        self.assertGreaterEqual(len(leaks), 2)
        self.assertNotIn("corp-private", repr([i.as_dict() for i in issues]))
        _hosts, records = textscan.parse_host_policy({"approved_by_role": "publication approver", "hosts": [
            {"host": self.host, "rationale": "synthetic reviewed exception for this test"}]})
        approved = vr.validate(self.doc, public=True, host_policy=records)
        self.assertNotIn("PUBLIC_LEAK", codes(approved))
        self.assertIn("HOST_OVERRIDE_APPLIED", {i.code for i in approved})  # never a silent clean scan

    def test_cli_withholds_host_and_flags_unscanned_release(self):
        d = Path(support.tmpdir())
        (d / "r.json").write_text(json.dumps(self.doc), encoding="utf-8")
        res = support.run_script("validate_report.py", d / "r.json", "--public")
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("corp-private", res.stdout + res.stderr)
        ok = support.run_script("validate_report.py", support.EXAMPLES / "baseline-report.json")
        self.assertIn("PUBLIC_SCAN_NOT_RUN", ok.stdout)


class DiagnosticPrivacy(unittest.TestCase):
    def test_unapproved_hostname_is_not_echoed_in_semantic_errors(self):
        host = "internal-review." + "fixture-sensitive" + ".org"
        doc = support.load_example("baseline")
        doc["evidence"][0]["target"] = host
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            for flags in ((), ("--json",)):
                result = support.run_script("validate_report.py", path, "--public", *flags)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(host, result.stdout + result.stderr)

    def test_secret_in_invalid_reference_is_not_echoed(self):
        marker = support.PLACEHOLDERS["{{FAKE_GH_TOKEN}}"]
        doc = support.load_example("baseline")
        doc["evidence"][0]["target"] = marker
        issues = vr.validate(doc)
        self.assertTrue(codes(issues))
        self.assertNotIn(marker, "\n".join(str(i) for i in issues))
        self.assertNotIn(marker, json.dumps([i.as_dict() for i in issues]))
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            report.write_text(json.dumps(doc), encoding="utf-8")
            for flags in ((), ("--json",)):
                result = support.run_script("validate_report.py", report, *flags)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(marker, result.stdout + result.stderr)

    def test_unknown_key_and_input_error_are_value_free(self):
        marker = support.PLACEHOLDERS["{{FAKE_GH_TOKEN}}"]
        doc = support.load_example("baseline")
        doc[marker] = "unexpected"
        self.assertNotIn(marker, json.dumps([i.as_dict() for i in vr.validate(doc)]))
        self.assertNotIn(marker, str(vr.InputError("duplicate key " + marker)))
        issue = vr.Issue("ERROR", "SYNTHETIC", "$.field", "line\n\x1b[31m\u202evalue")
        self.assertNotIn("\x1b", str(issue))
        self.assertNotIn("\u202e", str(issue))
        self.assertNotIn("\n", str(issue))


class FinalGateRegressions(unittest.TestCase):
    def clear_doc(self):
        return support.apply_ops(support.load_example("after_fix"), CLEAR_OPS)

    def test_owner_approval_is_not_active_test_isolation(self):
        doc = self.clear_doc()
        for evidence in doc["evidence"]:
            if evidence["kind"] == "test_run":
                evidence["execution_context"] = "owner_approved_environment"
        self.assertIn("ISOLATION_UNPROVEN", codes(vr.validate(doc, support.load_example("baseline"))))

    def test_inventory_gap_prevents_clear_even_when_checks_pass(self):
        doc = self.clear_doc()
        doc["inventory_coverage"][0]["gaps"].append({
            "id": "GAP-1", "reason": "binary fixture was not scanned", "disposition": "UNACCEPTED"})
        self.assertEqual(vr.expected_verdict(doc), "INCOMPLETE")
        got = codes(vr.validate(doc, support.load_example("baseline")))
        self.assertIn("INVENTORY_GAP_UNRESOLVED", got)
        self.assertIn("VERDICT_UNSUPPORTED", got)
        doc["inventory_coverage"] = []
        self.assertIn("INVENTORY_RECORD_MISSING", codes(vr.validate(doc, support.load_example("baseline"))))

    def test_inventory_exclusion_needs_human_approval(self):
        doc = self.clear_doc()
        gap = {"id": "GAP-1", "reason": "separate archive is outside the requested source scope",
               "disposition": "APPROVED_OUT_OF_SCOPE", "approved_by_role": "model", "approval_ref": "APP-01"}
        doc["inventory_coverage"][0]["gaps"].append(gap)
        self.assertIn("INVENTORY_EXCLUSION_UNAPPROVED", codes(vr.validate(doc, support.load_example("baseline"))))
        gap["approved_by_role"] = "scope owner"
        self.assertEqual(codes(vr.validate(doc, support.load_example("baseline"))), set())

    def test_inventory_target_and_capture_cannot_be_substituted(self):
        doc = self.clear_doc()
        doc["inventory_coverage"][0]["evidence_ids"] = ["EV-151"]
        self.assertIn("EVIDENCE_TARGET_MISMATCH", codes(vr.validate(doc, support.load_example("baseline"))))
        doc = self.clear_doc()
        doc["inventory_coverage"].append(dict(doc["inventory_coverage"][0]))
        self.assertIn("DUPLICATE_INVENTORY_TARGET", codes(vr.validate(doc, support.load_example("baseline"))))

    def test_invalid_risk_expiry_is_rejected(self):
        doc = support.load_example("after_fix")
        finding = next(f for f in doc["findings"] if f["id"] == "F-003")
        finding["status"] = "accepted_risk"
        finding["risk_acceptance"] = {
            "accepted_by_role": "risk owner", "reference": "APP-02", "expires_on": "2026-99-99"}
        self.assertIn("RISK_ACCEPTANCE_DATE_INVALID", codes(vr.validate(doc, support.load_example("baseline"))))


class SchemaSubset(unittest.TestCase):
    def test_bundled_schema_uses_only_enforced_keywords(self):
        schema = json.loads(vr.SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(vr.unsupported_schema_keywords(schema), [])

    def test_unsupported_keywords_are_reported(self):
        self.assertTrue(vr.unsupported_schema_keywords({"type": "string", "maxLength": 3}))
        self.assertTrue(vr.unsupported_schema_keywords({"type": "object", "additionalProperties": {"type": "string"}}))
        self.assertTrue(vr.unsupported_schema_keywords({"properties": {"a": {"oneOf": []}}}))


class InputHandling(unittest.TestCase):
    def _write(self, text):
        d = support.tmpdir()
        p = Path(d) / "r.json"
        p.write_text(text, encoding="utf-8")
        return p

    def test_size_bound_enforced_while_reading(self):
        p = self._write(json.dumps({"pad": "x" * 200}))
        saved = vr.MAX_INPUT_BYTES
        vr.MAX_INPUT_BYTES = 64
        try:
            with self.assertRaises(vr.InputError):
                vr.load_json(p)
        finally:
            vr.MAX_INPUT_BYTES = saved

    def test_duplicate_keys_rejected(self):
        p = self._write('{"a": 1, "a": 2}')
        with self.assertRaises(vr.InputError):
            vr.load_json(p)

    def test_nan_rejected(self):
        p = self._write('{"a": NaN}')
        with self.assertRaises(vr.InputError):
            vr.load_json(p)

    def test_unknown_field_is_schema_error(self):
        doc = support.load_example("baseline")
        doc["certified"] = True
        self.assertIn("SCHEMA", codes(vr.validate(doc)))

    def test_cli_exit_codes_and_disclaimer(self):
        ok = support.run_script("validate_report.py", support.EXAMPLES / "baseline-report.json")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("evidence authenticity is not verified", ok.stdout)
        bad = self._write(json.dumps(support.apply_ops(support.load_example("baseline"), [
            {"op": "set", "path": "verdict.overall", "value": "CLEAR_WITHIN_COVERED_SCOPE"}])))
        res = support.run_script("validate_report.py", bad, "--json")
        self.assertEqual(res.returncode, 1)
        out = json.loads(res.stdout)
        self.assertEqual(out["status"], "STRUCTURE_INVALID")
        self.assertIn("structure", out["verifies"])
        missing = support.run_script("validate_report.py", "/nonexistent/report.json")
        self.assertEqual(missing.returncode, 2)

    def test_secret_value_never_echoed(self):
        doc = support.apply_ops(support.load_example("baseline"), [
            {"op": "set", "path": "evidence[id=EV-007].summary", "value": "token {{FAKE_GH_TOKEN}}"}])
        p = self._write(json.dumps(doc))
        res = support.run_script("validate_report.py", p)
        self.assertEqual(res.returncode, 1)
        self.assertIn("RAW_SECRET", res.stdout)
        self.assertNotIn(support.PLACEHOLDERS["{{FAKE_GH_TOKEN}}"], res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
