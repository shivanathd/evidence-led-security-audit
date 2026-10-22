#!/usr/bin/env python3
"""Render a validated audit report (JSON) to Markdown, deterministically.

Safety properties:
- Report content is treated as text only. Nothing is executed, fetched or
  evaluated. Markdown/HTML control characters, terminal escapes and bidi
  override characters are neutralized; secret-shaped strings are redacted.
- Output is identical for identical input (no timestamps, stable ordering).
- --out is written relative to an anchored parent directory fd (see safeio):
  no symlink in any path component, no overwrite unless --force, forced
  writes use a temp file and a rename in the same directory. Files are 0600.
- The report is validated first. Invalid reports are refused unless
  --allow-invalid is given, which stamps a banner on every page. Reports with
  secret-shaped values (any URL userinfo, private-key blocks, tokens) are
  always refused; --allow-invalid never disables that.
- Rendered output is for internal review. Publication needs validate --public
  and a human publication approver.

Usage:
  python3 scripts/render_report.py REPORT.json [--baseline BASE.json]
                                  [--out FILE.md [--force]] [--allow-invalid]
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safeio  # noqa: E402
import textscan  # noqa: E402
import validate_report  # noqa: E402

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~#!])")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
HUMAN_PROOF = [
    "Authorization and any scope change",
    "Deployed image digest and source SHA mapping",
    "Credential rotation and revocation",
    "Risk acceptance and its expiry",
    "Approval to deploy fixes and to publish this report",
]


def t(value):
    """Neutralize arbitrary data for inline Markdown."""
    s = "" if value is None else str(value)
    s = textscan.redact(s)
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    s = _CONTROL.sub("", s)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def ids(values):
    return ", ".join(t(v) for v in values) if values else "none"


def row(cells):
    return "| " + " | ".join(cells) + " |"


def status_label(f):
    st = f["status"]
    if st == "fixed":
        basis = (f.get("fix_evidence") or {}).get("verification_basis", "?")
        if basis == "vendor_patch":
            return "fixed (vendor patch evidence; no exploit reproduction)"
        if basis == "not_execution_verified":
            return "fixed? NOT_EXECUTION_VERIFIED"
        return "fixed (discriminating before/after test)"
    return {"unknown": "UNKNOWN", "mitigated": "mitigated (not a fix)"}.get(st, st)


def render(report, issues):
    r = report
    errors = [i for i in issues if i.level == "ERROR"]
    kind = "Baseline security audit report" if r.get("report_kind") == "baseline" else "After-fix retest report"
    out = []
    if errors:
        out += ["> **STRUCTURE INVALID. Do not rely on this rendering.** %d validation error(s):" % len(errors), ">"]
        out += ["> - %s %s: %s" % (t(i.code), t(i.path), t(i.message)) for i in errors[:50]]
        out.append("")
    out += ["# %s: %s" % (kind, t(r.get("audit_id"))), ""]
    out += [row(["Field", "Value"]), row(["---", "---"])]
    out.append(row(["Report kind", t(r.get("report_kind"))]))
    if r.get("baseline_audit_id"):
        out.append(row(["Baseline", t(r["baseline_audit_id"])]))
    out.append(row(["Date", t(r.get("generated_on"))]))
    auth = r.get("authorization", {})
    out.append(row(["Authorized by (role)", t(auth.get("authorized_by_role"))]))
    out.append(row(["Authorization reference", t(auth.get("reference"))]))
    out.append(row(["Mode", t(auth.get("mode"))]))
    for k, v in sorted((auth.get("approvers") or {}).items()):
        out.append(row(["Approver: %s" % t(k), t(v)]))
    out.append("")

    v = r.get("verdict", {})
    out += ["## Verdict", "", "**%s**: %s" % (t(v.get("overall")), t(v.get("statement"))), ""]
    out += ["This verdict covers only the targets and checks listed below. It is not a statement "
            "that the system is free of vulnerabilities.", ""]

    gaps = [c for c in r.get("required_checks", []) if c.get("status") in ("BLOCKED", "NOT_RUN")]
    unknown = [f for f in r.get("findings", []) if f.get("status") == "unknown"]
    nev = [f for f in r.get("findings", []) if (f.get("fix_evidence") or {}).get("verification_basis") == "not_execution_verified"]
    out += ["## Coverage gaps", ""]
    for inventory_record in r.get("inventory_coverage", []):
        out.append("- Inventory %s: **%s**, evidence %s." % (
            t(inventory_record["target"]), t(inventory_record["status"]),
            t(", ".join(inventory_record["evidence_ids"]))))
        for gap in inventory_record["gaps"]:
            out.append("  - %s: %s (%s)." % (t(gap["id"]), t(gap["reason"]), t(gap["disposition"])))
    if not (gaps or unknown or nev or r.get("coverage_notes")):
        out += ["No gaps were recorded in the report. Gaps nobody recorded can still exist.", ""]
    for c in sorted(gaps, key=lambda c: c["id"]):
        out.append("- %s **%s** (%s): %s" % (t(c["id"]), t(c["status"]), t(c.get("title")), t(c.get("reason"))))
    for f in sorted(unknown, key=lambda f: f["id"]):
        out.append("- %s **UNKNOWN**: %s" % (t(f["id"]), t(f.get("unknown_reason"))))
    for f in sorted(nev, key=lambda f: f["id"]):
        out.append("- %s **NOT_EXECUTION_VERIFIED**: %s" % (t(f["id"]), t(f["fix_evidence"].get("not_execution_verified_reason"))))
    for n in r.get("coverage_notes", []):
        out.append("- %s" % t(n))
    out.append("")

    sc = r.get("scope", {})
    out += ["## Scope", "", row(["Target", "Kind", "Locator"]), row(["---", "---", "---"])]
    for tg in sorted(sc.get("targets", []), key=lambda x: x["id"]):
        out.append(row([t(tg["id"]), t(tg["kind"]), t(tg["locator"])]))
    out.append("")
    if sc.get("out_of_scope"):
        out += ["Out of scope: " + "; ".join(t(x) for x in sc["out_of_scope"]), ""]
    for q in sc.get("scope_requests", []):
        out.append("- Scope request (%s) for %s: %s, %s" % (t(q["change"]), t(q["target_id"]), t(q["status"]), t(q["reason"])))
    if sc.get("scope_requests"):
        out.append("")

    out += ["## Required checks", "", row(["ID", "Target", "Layer", "Status", "Evidence", "Check"]),
            row(["---"] * 6)]
    for c in sorted(r.get("required_checks", []), key=lambda x: x["id"]):
        out.append(row([t(c["id"]), t(c["target"]), t(c["layer"]), "**%s**" % t(c["status"]),
                        ids(c.get("evidence_ids")), t(c["title"])]))
    out.append("")

    out += ["## Findings", ""]
    findings = sorted(r.get("findings", []), key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), f["id"]))
    if not findings:
        out += ["No findings recorded.", ""]
    for f in findings:
        out += ["### %s: %s" % (t(f["id"]), t(f["title"])), ""]
        out.append("- Severity: %s; status: **%s**" % (t(f["severity"]), t(status_label(f))))
        out.append("- Target: %s; layer: %s; category: %s; dependency scope: %s"
                   % (t(f["target"]), t(f["layer"]), t(f["category"]), t(f["dependency_scope"])))
        if f.get("baseline_finding_id"):
            out.append("- Baseline finding: %s" % t(f["baseline_finding_id"]))
        out.append("- Evidence: %s; sources: %s" % (ids(f.get("evidence_ids")), ids(f.get("source_ids"))))
        if f.get("notes"):
            out.append("- Notes: %s" % t(f["notes"]))
        if f.get("mitigation"):
            m = f["mitigation"]
            out.append("- Mitigation (risk reduction, not a fix): %s; evidence %s; restart evidence %s"
                       % (t(m["description"]), ids(m.get("evidence_ids")), ids(m.get("restart_evidence_ids"))))
        fe = f.get("fix_evidence")
        if fe:
            out.append("- Fix basis: %s; before %s; after %s; valid-use %s; negative %s; vendor %s"
                       % (t(fe.get("verification_basis")), ids(fe.get("before_evidence_ids")), ids(fe.get("after_evidence_ids")),
                          ids(fe.get("positive_test_ids")), ids(fe.get("negative_test_ids")), ids(fe.get("vendor_fix_evidence_ids"))))
            out.append("- Deployed: %s; source SHA %s; deployed source SHA %s; image digest %s; runtime evidence %s"
                       % (t(fe.get("deployed_artifact")), t(fe.get("source_sha", "missing")),
                          t(fe.get("deployed_source_sha", "missing")), t(fe.get("image_digest", "missing")),
                          ids(fe.get("runtime_evidence_ids"))))
            if fe.get("package") or fe.get("fixed_build"):
                out.append("- Package %s; fixed build %s" % (t(fe.get("package", "missing")), t(fe.get("fixed_build", "missing"))))
            if fe.get("rotation_evidence_ids") or fe.get("revocation_evidence_ids"):
                out.append("- Rotation %s; revocation %s" % (ids(fe.get("rotation_evidence_ids")), ids(fe.get("revocation_evidence_ids"))))
        if f.get("refutation"):
            rf = f["refutation"]
            out.append("- Refutation: %s (basis %s); evidence %s" % (t(rf["result"]), t(rf.get("basis", "none")), ids(rf.get("evidence_ids"))))
        if f.get("risk_acceptance"):
            ra = f["risk_acceptance"]
            out.append("- Risk accepted by %s (%s) until %s" % (t(ra["accepted_by_role"]), t(ra["reference"]), t(ra["expires_on"])))
        out.append("")

    if r.get("fix_plan"):
        out += ["## Fix and retest plan", "", "Every step needs human approval. Nothing here was applied by the audit.", ""]
        for s in sorted(r["fix_plan"], key=lambda x: x["finding_id"]):
            rt = s["retest"]
            out += ["### %s" % t(s["finding_id"]), "",
                    "- Action: %s" % t(s["action"]), "- Owner role: %s" % t(s["owner_role"]),
                    "- Retest, valid use: %s" % t(rt["positive"]), "- Retest, negative: %s" % t(rt["negative"]),
                    "- Retest, runtime: %s" % t(rt["runtime_check"]), "- Rollback: %s" % t(s["rollback"]), ""]

    out += ["## Reviews", "", "Reviews are opinions. None of them counts as execution evidence.", ""]
    for rv in sorted(r.get("reviews", []), key=lambda x: x["id"]):
        fam = (" (%s)" % t(rv["model_family"])) if rv.get("model_family") else ""
        out.append("- %s %s%s, %s: %s [findings: %s]" % (t(rv["id"]), t(rv["reviewer_label"]), fam,
                                                         t(rv["independence"]), t(rv["summary"]), ids(rv.get("finding_ids"))))
    if not r.get("reviews"):
        out.append("- No reviews recorded.")
    out.append("")

    out += ["## Evidence index", "", row(["ID", "Kind", "Target", "Layer", "Collection", "Executed", "Context", "Summary"]),
            row(["---"] * 8)]
    for e in sorted(r.get("evidence", []), key=lambda x: x["id"]):
        out.append(row([t(e["id"]), t(e["kind"]), t(e["target"]), t(e["layer"]), t(e["collection_status"]),
                        t(e["executed"]), t(e.get("execution_context")), t(e["summary"])]))
    out.append("")

    out += ["## Sources", ""]
    for s in sorted(r.get("sources", []), key=lambda x: x["id"]):
        url = s["url"] if str(s.get("url", "")).startswith("https://") else "(invalid URL withheld)"
        out.append("- %s: %s, retrieved %s: %s" % (t(s["id"]), t(s["title"]), t(s["retrieved_on"]), t(url)))
    out += ["", "## Needs human proof", ""]
    out += ["- %s" % h for h in HUMAN_PROOF]
    out += ["", "---", "",
            "Rendered from structured data. Validation checks structure and internal consistency only; "
            "it does not prove any evidence is authentic.", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render an audit report to Markdown (safe, deterministic).")
    ap.add_argument("report")
    ap.add_argument("--baseline")
    ap.add_argument("--out")
    ap.add_argument("--force", action="store_true", help="replace an existing --out file (never a symlink)")
    ap.add_argument("--allow-invalid", action="store_true", help="render with an INVALID banner instead of refusing")
    args = ap.parse_args(argv)
    try:
        report = validate_report.load_json(args.report)
        base = validate_report.load_json(args.baseline) if args.baseline else None
    except validate_report.InputError as exc:
        print("ERROR INPUT: %s" % exc, file=sys.stderr)
        return 2
    if not isinstance(report, dict) or (args.baseline and not isinstance(base, dict)):
        print("ERROR INPUT: report and baseline must each be a JSON object", file=sys.stderr)
        return 2
    issues = validate_report.validate(report, base)
    errors = [i for i in issues if i.level == "ERROR"]
    if any(i.code == "RAW_SECRET" for i in errors):
        print("Refusing to render: the report contains secret-shaped values (store location and type only). "
              "--allow-invalid does not override this.", file=sys.stderr)
        return 1
    if errors and not args.allow_invalid:
        for i in errors:
            print(i, file=sys.stderr)
        print("Refusing to render an invalid report (use --allow-invalid to render with a banner).", file=sys.stderr)
        return 1
    if errors and any(i.code == "SCHEMA" for i in errors):
        print("Cannot render: the report does not match the schema.", file=sys.stderr)
        return 1
    text = render(report, issues)
    if args.out:
        try:
            safeio.safe_write(args.out, text, args.force)
        except OSError as exc:
            print("ERROR OUTPUT: %s" % validate_report.safe_diagnostic(exc), file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
