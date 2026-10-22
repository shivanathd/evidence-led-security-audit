#!/usr/bin/env python3
"""Validate the structure and internal consistency of an audit report.

What this checks: the report matches assets/report.schema.json, every
reference resolves, and status claims carry the kinds of evidence the skill
requires (for example, PASS is not backed only by model reviews or truncated
output, "fixed" has before/after or vendor-patch evidence, and the verdict
matches what the report contains).

What this cannot check: whether any evidence is real, current, or correctly
interpreted. A passing result means "structurally consistent", nothing more.

After-fix reports must be checked with --baseline; the baseline must itself
validate. --public adds the publication leak scan; STRUCTURE_OK without it
is not a release approval.

Usage:
  python3 scripts/validate_report.py REPORT.json [--baseline BASELINE.json]
                                    [--public [--host-policy FILE]] [--json]
Exit codes: 0 structure OK, 1 structural problems found, 2 unreadable input.
"""

import argparse
import json
import os
import re
import stat
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import textscan  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "assets" / "report.schema.json"
MAX_INPUT_BYTES = 10 * 1024 * 1024
EXEC_KINDS = {"command_output", "scanner_output", "test_run", "runtime_observation"}
ISOLATED = {"isolated_disposable"}
RUNTIME_LAYERS = {"runtime"}
ARTIFACT_LAYERS = {"image", "runtime"}
OVERCLAIM = re.compile(
    r"(?i)\b(secure|certified|certification|fully covered|full coverage|complete coverage|"
    r"100 ?%|guarantee[sd]?|no vulnerabilities|vulnerability[- ]free|bulletproof|unhackable|perfect)\b")
NON_HUMAN_ROLE = re.compile(r"(?i)\b(model|llm|assistant|subagent|agent|bot|automated|automation|self)\b")
STALE_SOURCE_DAYS = 7
STALE_EVIDENCE_DAYS = 30
# Minimum layers each target kind must have a required check for. A target's
# required_layers can add layers; nothing removes them.
REQUIRED_LAYERS = {
    "repository": {"dependency", "credential", "config"},
    "image": {"image"},
    "runtime": {"runtime", "config"},
    "saas_tenant": {"identity", "config"},
    "ci": {"process", "credential"},
    "agent_config": {"process"},
    "other": set(),
}
# Evidence layers that may support a PASS on each check layer.
SUPPORTING_LAYERS = {
    "source": {"source"},
    "dependency": {"dependency", "image", "runtime"},
    "image": {"image", "runtime"},
    "runtime": {"runtime"},
    "identity": {"identity", "config", "runtime"},
    "credential": {"credential", "source"},
    "config": {"config", "source", "runtime"},
    "process": {"process", "source"},
}
NON_DEPLOYED_KINDS = {"repository", "ci", "agent_config"}
PRIMARY_ADVISORY_KINDS = {"project_advisory", "vendor_advisory", "distro_advisory", "package_advisory"}
SUPPORTED_SCHEMA_KEYWORDS = {"type", "required", "properties", "additionalProperties", "enum", "items",
                             "$ref", "minItems", "minLength", "pattern"}
SCHEMA_ANNOTATIONS = {"$schema", "title", "description", "$defs"}


def safe_diagnostic(value):
    """Do not echo secret-shaped or terminal-control input through errors."""
    return textscan.diagnostic_text(value)


class Issue:
    def __init__(self, level, code, path, message):
        self.level, self.code = level, code
        self.path, self.message = safe_diagnostic(path), safe_diagnostic(message)

    def as_dict(self):
        return {"level": self.level, "code": self.code, "path": self.path, "message": self.message}

    def __str__(self):
        return "%s %s %s: %s" % (self.level, self.code, self.path, self.message)


# ------------------------------------------------------------------ loading
class InputError(Exception):
    def __init__(self, message):
        super().__init__(safe_diagnostic(message))


def _no_dupes(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise InputError("duplicate key %r" % k)
        obj[k] = v
    return obj


def _no_constants(name):
    raise InputError("non-standard JSON constant %s" % name)


def load_json(path):
    """Parse JSON, enforcing the size bound while reading (not from a stat)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise InputError("cannot open %s: %s" % (path, exc.strerror))
    chunks, total = [], 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InputError("%s is not a regular file" % path)
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise InputError("%s exceeds %d bytes" % (path, MAX_INPUT_BYTES))
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("%s is not UTF-8" % path)
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constants)
    except json.JSONDecodeError as exc:
        raise InputError("invalid JSON in %s: line %d" % (path, exc.lineno))


# ------------------------------------------------------------ schema subset
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}


def unsupported_schema_keywords(schema, path="#"):
    """List schema locations this subset validator would silently ignore."""
    if not isinstance(schema, dict):
        return [path]
    bad = []
    for key, val in schema.items():
        p = "%s/%s" % (path, key)
        if key in ("properties", "$defs"):
            if not isinstance(val, dict):
                bad.append(p)
                continue
            for name, sub in val.items():
                bad += unsupported_schema_keywords(sub, "%s/%s" % (p, name))
        elif key == "items":
            bad += unsupported_schema_keywords(val, p)
        elif key == "additionalProperties" and val is not False:
            bad.append(p)
        elif key == "type" and val not in _TYPES:
            bad.append(p)
        elif key not in SUPPORTED_SCHEMA_KEYWORDS and key not in SCHEMA_ANNOTATIONS:
            bad.append(p)
    return bad


def _resolve(schema, root):
    seen = 0
    while "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/") or seen > 32:
            raise ValueError("unsupported $ref %s" % ref)
        schema = root["$defs"][ref[len("#/$defs/"):]]
        seen += 1
    return schema


def schema_check(value, schema, root, path, out):
    schema = _resolve(schema, root)
    t = schema.get("type")
    if t:
        ok = isinstance(value, _TYPES[t]) and not (t == "integer" and isinstance(value, bool))
        if not ok:
            out.append(Issue("ERROR", "SCHEMA", path, "expected %s" % t))
            return
    if "enum" in schema and value not in schema["enum"]:
        out.append(Issue("ERROR", "SCHEMA", path, "value not in allowed set %s" % schema["enum"]))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            out.append(Issue("ERROR", "SCHEMA", path, "string too short"))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(Issue("ERROR", "SCHEMA", path, "does not match pattern %s" % schema["pattern"]))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(Issue("ERROR", "SCHEMA", path, "needs at least %d item(s)" % schema["minItems"]))
        if "items" in schema:
            for i, item in enumerate(value):
                schema_check(item, schema["items"], root, "%s[%d]" % (path, i), out)
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                out.append(Issue("ERROR", "SCHEMA", path, "missing required field %r" % key))
        props = schema.get("properties", {})
        for key, sub in value.items():
            if key in props:
                schema_check(sub, props[key], root, "%s.%s" % (path, key), out)
            elif schema.get("additionalProperties") is False:
                out.append(Issue("ERROR", "SCHEMA", path, "unexpected field %r" % key))


def _walk_strings(value, path="$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k in sorted(value):
            yield from _walk_strings(value[k], "%s.%s" % (path, k))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk_strings(item, "%s[%d]" % (path, i))


def _date(s):
    try:
        return date.fromisoformat(s)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- semantics
class Ctx:
    def __init__(self, report, issues):
        self.r = report
        self.issues = issues
        self.targets = {t["id"]: t for t in report["scope"]["targets"]}
        self.related = {t["id"]: set(t.get("related_targets", [])) for t in report["scope"]["targets"]}
        self.evidence = {e["id"]: e for e in report["evidence"]}
        self.sources = {s["id"]: s for s in report["sources"]}
        self.findings = {f["id"]: f for f in report["findings"]}
        self.generated = _date(report["generated_on"])
        self.current_from = None  # set to the baseline date for after-fix reports
        self.stale_sources = set()
        for s in report["sources"]:
            d = _date(s["retrieved_on"])
            if d and self.generated and (self.generated - d).days > STALE_SOURCE_DAYS:
                self.stale_sources.add(s["id"])

    def err(self, code, path, msg):
        self.issues.append(Issue("ERROR", code, path, msg))

    def warn(self, code, path, msg):
        self.issues.append(Issue("WARNING", code, path, msg))

    def target_ok(self, ev_target, target, related):
        if ev_target == target:
            return True
        return related and (ev_target in self.related.get(target, ()) or target in self.related.get(ev_target, ()))

    def support(self, ids, path, *, target, code_incomplete="PASS_ON_INCOMPLETE_EVIDENCE", related=True, clearing=True):
        """Return the evidence records usable as technical proof for ``target``.

        Model reviews and human attestations are never usable here. With
        ``clearing``, evidence must also be current: no stale primary
        sources, not older than the baseline, not older than the age limit.
        """
        usable = []
        for i, eid in enumerate(ids or []):
            e = self.evidence.get(eid)
            p = "%s[%d]" % (path, i)
            if e is None:
                self.err("DANGLING_REF", p, "evidence %r not found" % eid)
                continue
            if not self.target_ok(e["target"], target, related):
                self.err("EVIDENCE_TARGET_MISMATCH", p, "evidence %r was collected for target %r, not %r"
                         % (eid, e["target"], target))
                continue
            if e["kind"] == "model_review":
                self.err("MODEL_ONLY_EVIDENCE", p, "model output %r is a review, not execution proof" % eid)
                continue
            if e["kind"] == "human_attestation":
                self.err("ATTESTATION_NOT_ENOUGH", p,
                         "%r is an attestation; this claim needs a tool-captured result" % eid)
                continue
            if e["collection_status"] != "complete":
                self.err(code_incomplete, p, "evidence %r is %s; report the item as BLOCKED or UNKNOWN"
                         % (eid, e["collection_status"]))
                continue
            if e["kind"] in EXEC_KINDS and not e["executed"]:
                self.err("UNRUN_EVIDENCE", p, "evidence %r was not executed" % eid)
                continue
            if e["kind"] == "test_run" and e["execution_context"] not in ISOLATED:
                self.err("ISOLATION_UNPROVEN", p, "test %r did not run in host-enforced disposable isolation; owner approval alone is insufficient" % eid)
                continue
            if e["executed"] and e["execution_context"] == "unisolated":
                self.err("ISOLATION_UNPROVEN", p, "evidence %r ran unisolated" % eid)
                continue
            if clearing:
                stale = sorted(s for s in e.get("source_ids", []) if s in self.stale_sources)
                d = _date(e["collected_on"])
                if stale:
                    self.err("STALE_SOURCE", p, "evidence %r relies on source(s) not refreshed this run: %s"
                             % (eid, ", ".join(stale)))
                    continue
                if d and self.current_from and d < self.current_from:
                    self.err("HISTORICAL_EVIDENCE_AS_CURRENT", p,
                             "evidence %r predates the baseline; it cannot show the current state" % eid)
                    continue
                if d and self.generated and (self.generated - d).days > STALE_EVIDENCE_DAYS:
                    self.err("STALE_EVIDENCE", p, "evidence %r is older than %d days" % (eid, STALE_EVIDENCE_DAYS))
                    continue
            usable.append(e)
        return usable


def _check_ids_unique(ctx):
    sections = [("scope.targets", ctx.r["scope"]["targets"])]
    sections += [(s, ctx.r[s]) for s in ("evidence", "required_checks", "findings", "sources", "reviews")]
    for name, items in sections:
        seen = set()
        for i, item in enumerate(items):
            if item["id"] in seen:
                ctx.err("DUPLICATE_ID", "$.%s[%d]" % (name, i), "duplicate id %r" % item["id"])
            seen.add(item["id"])


def _check_authorization(ctx):
    a = ctx.r["authorization"]
    if not a["confirmed"]:
        ctx.err("AUTHORIZATION_MISSING", "$.authorization.confirmed", "written owner authorization is required")
    if a["mode"] == "approved_changes" and not a.get("approved_actions"):
        ctx.err("AUTHORIZATION_MISSING", "$.authorization.approved_actions", "approved_changes mode needs listed actions")
    roles = [("$.authorization.authorized_by_role", a["authorized_by_role"])]
    roles += [("$.authorization.approvers.%s" % k, v) for k, v in sorted(a["approvers"].items())]
    for i, req in enumerate(ctx.r["scope"]["scope_requests"]):
        if req.get("approved_by_role"):
            roles.append(("$.scope.scope_requests[%d].approved_by_role" % i, req["approved_by_role"]))
    for i, c in enumerate(ctx.r["required_checks"]):
        if c.get("approved_by_role"):
            roles.append(("$.required_checks[%d].approved_by_role" % i, c["approved_by_role"]))
    for i, f in enumerate(ctx.r["findings"]):
        if f.get("risk_acceptance"):
            roles.append(("$.findings[%d].risk_acceptance.accepted_by_role" % i, f["risk_acceptance"]["accepted_by_role"]))
    for i, e in enumerate(ctx.r["evidence"]):
        if e.get("attested_by_role"):
            roles.append(("$.evidence[%d].attested_by_role" % i, e["attested_by_role"]))
    for path, role in roles:
        if NON_HUMAN_ROLE.search(role):
            ctx.err("SELF_APPROVAL", path, "approvals and attestations must name a human role, not a model or automation")


def _check_scope(ctx):
    scope = ctx.r["scope"]
    out = {s.strip() for s in scope["out_of_scope"]}
    for i, t in enumerate(scope["targets"]):
        if t["id"] in out:
            ctx.err("SCOPE_CONFLICT", "$.scope", "target %r is also listed out of scope" % t["id"])
        for j, rid in enumerate(t.get("related_targets", [])):
            if rid == t["id"] or rid not in ctx.targets:
                ctx.err("SCOPE_VIOLATION", "$.scope.targets[%d].related_targets[%d]" % (i, j),
                        "related target %r must be a different listed target" % rid)
    for i, req in enumerate(scope["scope_requests"]):
        p = "$.scope.scope_requests[%d]" % i
        approved = req["status"] == "approved" and req.get("approved_by_role") and req.get("approval_ref")
        if req["status"] == "approved" and not approved:
            ctx.err("SCOPE_SELF_EXPANDED", p, "approval needs approved_by_role and approval_ref")
        if req["change"] == "expand" and req["target_id"] in ctx.targets and not approved:
            ctx.err("SCOPE_SELF_EXPANDED", p, "target %r was added without owner approval" % req["target_id"])
        if req["change"] == "narrow" and req["target_id"] not in ctx.targets and not approved:
            ctx.err("SCOPE_NARROWED", p, "target %r was removed without owner approval" % req["target_id"])
    for section in ("evidence", "required_checks", "findings"):
        for i, item in enumerate(ctx.r[section]):
            if item["target"] not in ctx.targets:
                ctx.err("SCOPE_VIOLATION", "$.%s[%d].target" % (section, i),
                        "%r is not an approved target; findings do not expand scope" % item["target"])
    for i, m in enumerate(ctx.r.get("inventory_manifests", [])):
        if m["target"] not in ctx.targets:
            ctx.err("SCOPE_VIOLATION", "$.inventory_manifests[%d].target" % i, "unknown target %r" % m["target"])


def _check_evidence(ctx):
    for i, e in enumerate(ctx.r["evidence"]):
        p = "$.evidence[%d]" % i
        d = _date(e["collected_on"])
        if d is None:
            ctx.err("SCHEMA", p + ".collected_on", "invalid date")
        elif ctx.generated and d > ctx.generated:
            ctx.err("DATE_ORDER", p + ".collected_on", "evidence dated after the report")
        if e["executed"] and e["execution_context"] == "not_executed":
            ctx.err("CONTEXT_CONFLICT", p, "executed evidence needs an execution_context")
        if e["kind"] in ("human_attestation", "model_review") and e["executed"]:
            ctx.err("CONTEXT_CONFLICT", p, "attestations and reviews are not executed results")
        if e["kind"] == "human_attestation" and not e.get("attested_by_role"):
            ctx.err("ATTESTATION_ROLE_MISSING", p, "human attestation needs attested_by_role")
        for j, sid in enumerate(e.get("source_ids", [])):
            if sid not in ctx.sources:
                ctx.err("DANGLING_REF", "%s.source_ids[%d]" % (p, j), "source %r not found" % sid)


def _check_sources(ctx):
    for i, s in enumerate(ctx.r["sources"]):
        p = "$.sources[%d].retrieved_on" % i
        d = _date(s["retrieved_on"])
        if d is None:
            ctx.err("SCHEMA", p, "invalid date")
        elif ctx.generated and d > ctx.generated:
            ctx.err("DATE_ORDER", p, "source retrieved after the report date")
        elif s["id"] in ctx.stale_sources:
            ctx.warn("STALE_SOURCE", p, "refresh primary sources each run; stale sources cannot support clearance")


def matrix_gaps(report):
    """Return (target_id, layer) pairs that have no required check."""
    have = {(c["target"], c["layer"]) for c in report["required_checks"]}
    gaps = []
    for t in report["scope"]["targets"]:
        need = set(REQUIRED_LAYERS.get(t["kind"], set())) | set(t.get("required_layers", []))
        gaps += [(t["id"], layer) for layer in sorted(need) if (t["id"], layer) not in have]
        if not need and not any(c["target"] == t["id"] for c in report["required_checks"]):
            gaps.append((t["id"], "any"))
    return gaps


def _check_checks(ctx):
    manifests = {}
    for m in ctx.r.get("inventory_manifests", []):
        manifests.setdefault(m["target"], set()).add(m["path"])
    for tid, layer in matrix_gaps(ctx.r):
        ctx.err("CHECK_MATRIX_GAP", "$.required_checks",
                "target %r has no required %s check; omitted checks cannot clear" % (tid, layer))
    for i, c in enumerate(ctx.r["required_checks"]):
        p = "$.required_checks[%d]" % i
        st = c["status"]
        if st in ("BLOCKED", "NOT_RUN", "NOT_APPLICABLE") and not c.get("reason", "").strip():
            ctx.err("REASON_MISSING", p + ".reason", "%s needs a reason" % st)
        if st == "FAIL" and not c["evidence_ids"]:
            ctx.err("EVIDENCE_MISSING", p, "FAIL needs evidence")
        if st == "NOT_APPLICABLE":
            if not ctx.support(c["evidence_ids"], p + ".evidence_ids", target=c["target"], related=False):
                ctx.err("NA_UNPROVEN", p, "NOT_APPLICABLE needs evidence; required checks are not optional")
            if not c.get("approved_by_role"):
                ctx.err("NA_UNAPPROVED", p, "NOT_APPLICABLE needs a human approved_by_role")
        if st != "PASS":
            if st != "NOT_APPLICABLE":
                for j, eid in enumerate(c["evidence_ids"]):
                    e = ctx.evidence.get(eid)
                    if e is None:
                        ctx.err("DANGLING_REF", "%s.evidence_ids[%d]" % (p, j), "evidence %r not found" % eid)
                    elif e["target"] != c["target"]:
                        ctx.err("EVIDENCE_TARGET_MISMATCH", "%s.evidence_ids[%d]" % (p, j),
                                "evidence %r is for target %r" % (eid, e["target"]))
            continue
        if not c["evidence_ids"]:
            ctx.err("EVIDENCE_MISSING", p, "PASS needs evidence")
            continue
        usable = ctx.support(c["evidence_ids"], p + ".evidence_ids", target=c["target"], related=False)
        if len(usable) != len(c["evidence_ids"]):
            continue
        layers = {e["layer"] for e in usable}
        if c["layer"] == "runtime" and not layers & RUNTIME_LAYERS:
            ctx.err("RUNTIME_PROOF_MISSING", p, "runtime PASS needs runtime-layer evidence; source or CLI versions do not prove the served runtime")
        elif c["layer"] == "image" and not layers & ARTIFACT_LAYERS:
            ctx.err("RUNTIME_PROOF_MISSING", p, "image PASS needs image or runtime evidence")
        elif not layers & SUPPORTING_LAYERS[c["layer"]]:
            ctx.err("LAYER_MISMATCH", p, "%s PASS needs evidence from layer(s) %s"
                    % (c["layer"], ", ".join(sorted(SUPPORTING_LAYERS[c["layer"]]))))
        if c["layer"] == "dependency":
            expected = manifests.get(c["target"], set())
            covered = set(c.get("covers", []))
            if not expected:
                ctx.err("INVENTORY_NOT_RECONCILED", p, "dependency PASS needs inventoried manifests for this target; "
                        "if none exist, use NOT_APPLICABLE with evidence and approval")
            missing = sorted(expected - covered)
            if missing:
                ctx.err("MANIFEST_COVERAGE_GAP", p, "PASS does not cover %d inventoried manifest(s): %s"
                        % (len(missing), ", ".join(missing[:5])))
            if covered - expected:
                ctx.err("MANIFEST_COVERAGE_GAP", p, "covers lists %d path(s) not in the inventory" % len(covered - expected))


def _has_artifact(e):
    return e.get("image_digest") or e.get("source_sha")


def deployment_relevant(report, f):
    kinds = {t["id"]: t["kind"] for t in report["scope"]["targets"]}
    return not (kinds.get(f["target"]) in NON_DEPLOYED_KINDS and f["dependency_scope"] in ("test_only", "dev_only"))


def _check_fixed(ctx, f, p):
    fe = f.get("fix_evidence")
    if not fe:
        code = "MITIGATION_NOT_FIX" if f.get("mitigation") else "FIX_EVIDENCE_MISSING"
        ctx.err(code, p, "fixed needs fix_evidence; mitigations are reported as 'mitigated'")
        return
    fp = p + ".fix_evidence"

    def sup(key, clearing=True):
        return ctx.support(fe.get(key, []), "%s.%s" % (fp, key), target=f["target"],
                           code_incomplete="FIX_EVIDENCE_INCOMPLETE", clearing=clearing)

    basis = fe["verification_basis"]
    src, dep, digest = fe.get("source_sha"), fe.get("deployed_source_sha"), fe.get("image_digest")
    after, positive, runtime = sup("after_evidence_ids"), sup("positive_test_ids"), sup("runtime_evidence_ids")
    if not fe["after_evidence_ids"]:
        ctx.err("FIX_EVIDENCE_MISSING", fp, "after evidence is required")
    if not fe["positive_test_ids"]:
        ctx.err("VALID_USE_UNPROVEN", fp, "legitimate-use regression tests are required")
    for e in positive:
        if e.get("outcome") != "pass":
            ctx.err("VALID_USE_UNPROVEN", fp, "valid-use test %r did not pass" % e["id"])
    for e in after + positive:
        if not _has_artifact(e):
            ctx.err("ARTIFACT_ASSOCIATION_MISSING", fp, "evidence %r is not tied to a source SHA or image digest" % e["id"])
        elif src and e.get("source_sha") and e["source_sha"] != src:
            ctx.err("ARTIFACT_ASSOCIATION_MISSING", fp, "evidence %r is for a different source SHA" % e["id"])
        elif digest and e.get("image_digest") and e["image_digest"] != digest:
            ctx.err("ARTIFACT_ASSOCIATION_MISSING", fp, "evidence %r is for a different image digest" % e["id"])
    if basis == "behavior_test":
        before, negative = sup("before_evidence_ids", clearing=False), sup("negative_test_ids")
        if not fe.get("before_evidence_ids") or not fe.get("negative_test_ids"):
            ctx.err("FIX_EVIDENCE_MISSING", fp, "behavior_test needs before evidence and negative tests")
        pair = any(b.get("test_ref") and b.get("test_ref") == a.get("test_ref") and b.get("outcome") == "fail"
                   and a.get("outcome") == "pass" and _has_artifact(b) and _has_artifact(a)
                   and (b.get("image_digest"), b.get("source_sha")) != (a.get("image_digest"), a.get("source_sha"))
                   for b in before for a in after)
        if not pair:
            ctx.err("DISCRIMINATING_TEST_MISSING", fp,
                    "need one security test that fails on the old artifact and passes on the new one")
        for e in negative:
            if e.get("outcome") != "pass":
                ctx.err("NEGATIVE_TEST_FAILED", fp, "negative test %r did not pass" % e["id"])
    elif basis == "vendor_patch":
        vendor = sup("vendor_fix_evidence_ids")
        pkg, build = fe.get("package"), fe.get("fixed_build")
        if not f["source_ids"]:
            ctx.err("SOURCE_MISSING", p, "vendor_patch needs a primary advisory source")
        if not pkg or not build:
            ctx.err("BACKPORT_UNPROVEN", fp, "vendor_patch needs package and fixed_build coordinates")
        else:
            linked = [e for e in vendor if e["kind"] == "package_advisory" and e.get("package") == pkg
                      and e.get("build") == build
                      and any(ctx.sources.get(s, {}).get("kind") in PRIMARY_ADVISORY_KINDS for s in e.get("source_ids", []))]
            if not linked:
                ctx.err("BACKPORT_UNPROVEN", fp, "need package-advisory evidence naming this package and fixed build, "
                        "linked to a primary advisory; a version comparison alone is not enough")
            installed = [e for e in after + runtime if e["kind"] != "package_advisory"
                         and e.get("package") == pkg and e.get("build") == build]
            if not installed:
                ctx.err("RUNTIME_MAPPING_MISSING", fp, "no captured evidence shows the fixed build installed on the target")
            elif fe["deployed_artifact"] and not any(e["layer"] in ARTIFACT_LAYERS and digest
                                                     and e.get("image_digest") == digest for e in installed):
                ctx.err("RUNTIME_MAPPING_MISSING", fp, "show the fixed build inside the deployed image digest")
    elif basis == "not_execution_verified":
        if not fe.get("not_execution_verified_reason", "").strip():
            ctx.err("REASON_MISSING", fp, "explain why the baseline could not be run safely")
    if fe["deployed_artifact"]:
        if not src or not dep or src != dep:
            ctx.err("SHA_MISMATCH", fp, "source_sha (the fixed commit) must equal deployed_source_sha "
                    "(the commit the deployed image was built from)")
        if not digest:
            ctx.err("ARTIFACT_BINDING_MISSING", fp, "deployed fixes need the deployed image_digest; a source SHA is not an image digest")
        else:
            if not any(e["layer"] in ARTIFACT_LAYERS and e.get("image_digest") == digest and src
                       and src in (e.get("source_sha"), e.get("deployed_source_sha")) for e in runtime):
                ctx.err("BUILD_MAPPING_MISSING", fp, "need image or runtime evidence mapping the source SHA to the deployed image digest")
            if ctx.targets.get(f["target"], {}).get("kind") != "image" and not any(
                    e["layer"] == "runtime" and e.get("image_digest") == digest for e in runtime):
                ctx.err("RUNTIME_PROOF_MISSING", fp, "need runtime-layer evidence from the running service on the deployed digest")
        for e in runtime:
            if digest and e.get("image_digest") and e["image_digest"] != digest:
                ctx.err("DIGEST_MISMATCH", fp, "runtime evidence %r reports a different image digest" % e["id"])
            if src and e.get("deployed_source_sha") and e["deployed_source_sha"] != src:
                ctx.err("SHA_MISMATCH", fp, "runtime evidence %r reports a different deployed source SHA" % e["id"])
    else:
        if not fe.get("not_deployed_reason", "").strip():
            ctx.err("FIX_EVIDENCE_MISSING", fp, "deployed_artifact false needs not_deployed_reason")
        if deployment_relevant(ctx.r, f):
            ctx.err("UNDEPLOYED_FIX", fp, "the fix is not deployed; keep the finding open until the deployed artifact is verified")
        elif not any(e["layer"] in ARTIFACT_LAYERS for e in runtime):
            ctx.err("UNDEPLOYED_FIX", fp, "show the shipped image or runtime excludes the test or dev-only component")
    if fe.get("requires_config") and not sup("config_evidence_ids"):
        ctx.err("CONFIG_EVIDENCE_MISSING", fp, "the fix depends on non-default configuration; show the effective config")
    if f["category"] == "credential_exposure":
        if not sup("rotation_evidence_ids") or not sup("revocation_evidence_ids"):
            ctx.err("ROTATION_EVIDENCE_MISSING", fp, "removing a secret from code is not a fix; captured rotation and revocation evidence are required")


def _check_refuted(ctx, f, p):
    ref = f.get("refutation")
    if not ref or not ref["attempted"] or ref["result"] != "refuted":
        ctx.err("REFUTATION_INCOMPLETE", p, "refuted needs a completed refutation; use 'unknown' when the trace is incomplete")
        return
    if not ref["evidence_ids"]:
        ctx.err("REFUTATION_INCOMPLETE", p, "refutation needs evidence")
        return
    usable = ctx.support(ref["evidence_ids"], p + ".refutation.evidence_ids", target=f["target"],
                         code_incomplete="REFUTATION_INCOMPLETE")
    if len(usable) != len(ref["evidence_ids"]):
        return
    layers = {e["layer"] for e in usable}
    basis = ref.get("basis")
    if not basis:
        ctx.err("REFUTATION_INCOMPLETE", p, "refutation needs a basis")
    elif basis in ("test_only", "not_present_in_artifact") and not layers & ARTIFACT_LAYERS:
        ctx.err("TEST_ONLY_UNPROVEN", p, "show the shipped image or runtime excludes the component")
    elif basis == "vendor_backport" and not any(e["kind"] == "package_advisory" for e in usable):
        ctx.err("BACKPORT_UNPROVEN", p, "vendor backports need package or advisory evidence, not a version comparison")
    elif basis in ("version_not_affected", "config_not_enabled") and not layers & ARTIFACT_LAYERS:
        ctx.err("RUNTIME_PROOF_MISSING", p, "show the deployed version or effective config, not only source")


def _check_findings(ctx):
    kind = ctx.r["report_kind"]
    planned = {s["finding_id"] for s in ctx.r["fix_plan"]}
    for i, f in enumerate(ctx.r["findings"]):
        p = "$.findings[%d]" % i
        st = f["status"]
        for j, sid in enumerate(f["source_ids"]):
            if sid not in ctx.sources:
                ctx.err("DANGLING_REF", "%s.source_ids[%d]" % (p, j), "source %r not found" % sid)
            elif sid in ctx.stale_sources and st in ("fixed", "refuted"):
                ctx.err("STALE_SOURCE", "%s.source_ids[%d]" % (p, j), "a %s claim cannot rest on a stale source" % st)
        if f["category"] == "vulnerable_component" and not f["source_ids"]:
            ctx.err("SOURCE_MISSING", p, "component findings need a primary advisory source")
        if kind == "after_fix" and not f.get("baseline_finding_id"):
            ctx.err("REPORT_KIND_MIXING", p, "after-fix findings need baseline_finding_id (or 'NEW')")
        if kind == "baseline" and (st == "fixed" or f.get("fix_evidence")):
            ctx.err("REPORT_KIND_MIXING", p, "baseline reports record pre-fix state; put fixes in a separate after-fix report")
            continue
        for j, eid in enumerate(f["evidence_ids"]):
            e = ctx.evidence.get(eid)
            if e is None:
                ctx.err("DANGLING_REF", "%s.evidence_ids[%d]" % (p, j), "evidence %r not found" % eid)
            elif not ctx.target_ok(e["target"], f["target"], True):
                ctx.err("EVIDENCE_TARGET_MISMATCH", "%s.evidence_ids[%d]" % (p, j),
                        "evidence %r is for unrelated target %r" % (eid, e["target"]))
        if st in ("open", "mitigated", "fixed", "accepted_risk"):
            recs = [ctx.evidence.get(e) for e in f["evidence_ids"]]
            if not f["evidence_ids"]:
                ctx.err("EVIDENCE_MISSING", p, "finding needs evidence")
            elif all(r is not None and r["kind"] == "model_review" for r in recs):
                ctx.err("MODEL_ONLY_EVIDENCE", p, "a model opinion alone makes a finding 'unknown', not confirmed")
        if st == "unknown" and not f.get("unknown_reason", "").strip():
            ctx.err("UNKNOWN_REASON_MISSING", p, "say what evidence is missing")
        if st == "mitigated":
            m = f.get("mitigation")
            if not m:
                ctx.err("MITIGATION_MISSING", p, "mitigated needs a mitigation record")
            else:
                if not ctx.support(m["evidence_ids"], p + ".mitigation.evidence_ids", target=f["target"], clearing=False):
                    ctx.err("MITIGATION_MISSING", p, "mitigation needs effective-config evidence")
                if m["requires_restart"] and not ctx.support(m.get("restart_evidence_ids", []), p + ".mitigation.restart_evidence_ids",
                                                             target=f["target"], clearing=False):
                    ctx.err("RESTART_UNPROVEN", p, "show every worker was restarted after the setting changed")
        if st == "fixed":
            _check_fixed(ctx, f, p)
        if st == "refuted":
            _check_refuted(ctx, f, p)
        if st in ("open", "unknown") and f.get("refutation", {}).get("result") == "refuted":
            ctx.err("STATUS_CONFLICT", p, "refutation says refuted but status is %s" % st)
        if st == "accepted_risk":
            ra = f.get("risk_acceptance")
            if not ra:
                ctx.err("RISK_ACCEPTANCE_MISSING", p, "accepted_risk needs a named human role and reference")
            elif _date(ra["expires_on"]) is None:
                ctx.err("RISK_ACCEPTANCE_DATE_INVALID", p, "risk acceptance needs a valid calendar expiry date")
            elif ctx.generated and _date(ra["expires_on"]) <= ctx.generated:
                ctx.err("RISK_ACCEPTANCE_EXPIRED", p, "risk acceptance has expired")
        if kind == "baseline" and st in ("open", "mitigated", "unknown") and f["id"] not in planned:
            ctx.err("FIX_PLAN_MISSING", p, "open, mitigated and unknown findings need a fix or evidence plan")
    for i, step in enumerate(ctx.r["fix_plan"]):
        p = "$.fix_plan[%d]" % i
        if step["finding_id"] not in ctx.findings:
            ctx.err("DANGLING_REF", p, "finding %r not found" % step["finding_id"])
        if not step["requires_human_approval"]:
            ctx.err("HUMAN_APPROVAL_REQUIRED", p, "changes, deploys and rotations need human approval")


def _check_reviews(ctx):
    primary = (ctx.r.get("primary_model_family") or "").strip().lower()
    for i, rv in enumerate(ctx.r["reviews"]):
        p = "$.reviews[%d]" % i
        if rv["counts_as_execution_proof"]:
            ctx.err("MODEL_VOTE_AS_PROOF", p, "reviews and votes are never execution proof")
        if rv["independence"] == "different_model":
            fam = (rv.get("model_family") or "").strip().lower()
            if not fam or not primary or fam == primary:
                ctx.err("CROSS_MODEL_MISLABEL", p, "different_model needs a model_family distinct from primary_model_family")
        for j, fid in enumerate(rv["finding_ids"]):
            if fid not in ctx.findings:
                ctx.err("DANGLING_REF", "%s.finding_ids[%d]" % (p, j), "finding %r not found" % fid)
        for j, eid in enumerate(rv["input_evidence_ids"]):
            e = ctx.evidence.get(eid)
            if e is None:
                ctx.err("DANGLING_REF", "%s.input_evidence_ids[%d]" % (p, j), "evidence %r not found" % eid)
            elif rv["independence"] != "human" and e["redaction"] == "raw_local_only":
                ctx.err("UNREDACTED_HANDOFF", "%s.input_evidence_ids[%d]" % (p, j), "redact before handing evidence to a model or tool")


def inventory_incomplete(report):
    records = report.get("inventory_coverage", [])
    required = {t["id"] for t in report["scope"]["targets"] if t["kind"] == "repository"}
    if required - {r["target"] for r in records}:
        return True
    return any(r["status"] != "COMPLETE" or
               any(g["disposition"] == "UNACCEPTED" for g in r["gaps"])
               for r in records)


def _check_inventory_coverage(ctx):
    seen = set()
    for i, record in enumerate(ctx.r["inventory_coverage"]):
        p = "$.inventory_coverage[%d]" % i
        target = record["target"]
        if target in seen:
            ctx.err("DUPLICATE_INVENTORY_TARGET", p, "inventory target is repeated")
        seen.add(target)
        if target not in ctx.targets:
            ctx.err("UNAPPROVED_TARGET", p, "inventory must refer to an authorized target")
        gap_ids = set()
        for j, gap in enumerate(record["gaps"]):
            gp = "%s.gaps[%d]" % (p, j)
            if gap["id"] in gap_ids:
                ctx.err("DUPLICATE_INVENTORY_GAP", gp, "gap ID is repeated")
            gap_ids.add(gap["id"])
            if gap["disposition"] == "APPROVED_OUT_OF_SCOPE":
                role = gap.get("approved_by_role", "").strip()
                if not role or NON_HUMAN_ROLE.search(role) or not gap.get("approval_ref", "").strip():
                    ctx.err("INVENTORY_EXCLUSION_UNAPPROVED", gp, "accepted exclusion needs human role and approval reference")
            elif record["status"] == "COMPLETE":
                ctx.err("INVENTORY_GAP_UNRESOLVED", gp, "unaccepted inventory gap cannot be labeled COMPLETE")
        if record["status"] == "COMPLETE":
            proof = ctx.support(record["evidence_ids"], p + ".evidence_ids", target=target,
                                related=False)
            if not proof or not any(e["kind"] in EXEC_KINDS and e["executed"] for e in proof):
                ctx.err("INVENTORY_CAPTURE_MISSING", p, "COMPLETE inventory needs same-target captured execution evidence")
        elif not record["gaps"] and not record.get("reason", "").strip():
            ctx.err("INVENTORY_REASON_MISSING", p, "incomplete inventory needs a reason or recorded gaps")
        else:
            for eid in record["evidence_ids"]:
                if eid not in ctx.evidence:
                    ctx.err("DANGLING_REF", p, "inventory evidence reference does not exist")
    missing = {t["id"] for t in ctx.r["scope"]["targets"] if t["kind"] == "repository"} - seen
    if missing:
        ctx.err("INVENTORY_RECORD_MISSING", "$.inventory_coverage", "every repository target needs an inventory record")


def expected_verdict(report):
    checks = report["required_checks"]
    findings = report["findings"]
    if not checks or matrix_gaps(report) or inventory_incomplete(report):
        return "INCOMPLETE"
    if any(c["status"] in ("BLOCKED", "NOT_RUN") for c in checks):
        return "INCOMPLETE"
    if any(f["status"] == "unknown" for f in findings):
        return "INCOMPLETE"
    if any(f["status"] == "fixed" and (f.get("fix_evidence") or {}).get("verification_basis") == "not_execution_verified"
           for f in findings):
        return "INCOMPLETE"
    undeployed = any(f["status"] == "fixed" and not (f.get("fix_evidence") or {}).get("deployed_artifact")
                     and deployment_relevant(report, f) for f in findings)
    if (undeployed or any(c["status"] == "FAIL" for c in checks)
            or any(f["status"] in ("open", "mitigated", "accepted_risk") for f in findings)):
        return "ISSUES_OPEN"
    return "CLEAR_WITHIN_COVERED_SCOPE"


def _check_verdict(ctx):
    v = ctx.r["verdict"]
    exp = expected_verdict(ctx.r)
    if not ctx.r["required_checks"]:
        ctx.err("EMPTY_COVERAGE", "$.required_checks", "a report with no required checks cannot clear anything")
    if v["overall"] != exp:
        ctx.err("VERDICT_UNSUPPORTED", "$.verdict.overall", "report contents support %s, not %s" % (exp, v["overall"]))
    texts = [("$.verdict.statement", v["statement"])]
    texts += [("$.coverage_notes[%d]" % i, n) for i, n in enumerate(ctx.r["coverage_notes"])]
    for path, text in texts:
        m = OVERCLAIM.search(text)
        if m:
            ctx.err("OVERCLAIM", path, "avoid absolute claims such as %r" % m.group(0))
    if exp == "INCOMPLETE" and not ctx.r["coverage_notes"]:
        ctx.err("COVERAGE_NOTES_MISSING", "$.coverage_notes", "INCOMPLETE reports must explain the gaps")


def _check_against_baseline(ctx, base):
    r = ctx.r
    if r.get("baseline_audit_id") != base.get("audit_id"):
        ctx.err("BASELINE_MISMATCH", "$.baseline_audit_id", "does not match the baseline audit_id")
    bdate = _date(base["generated_on"])
    if bdate and ctx.generated and bdate > ctx.generated:
        ctx.err("BASELINE_MISMATCH", "$.generated_on", "after-fix report predates its baseline")
    narrowed = {q["target_id"] for q in r["scope"]["scope_requests"]
                if q["change"] == "narrow" and q["status"] == "approved" and q.get("approval_ref")}
    for t in base["scope"]["targets"]:
        if t["id"] not in ctx.targets and t["id"] not in narrowed:
            ctx.err("SCOPE_NARROWED", "$.scope.targets", "baseline target %r dropped without approved narrowing" % t["id"])
        elif t["id"] in ctx.targets:
            now = ctx.targets[t["id"]]
            if (now["kind"], now["locator"]) != (t["kind"], t["locator"]) or \
                    not set(t.get("required_layers", [])) <= set(now.get("required_layers", [])):
                ctx.err("SCOPE_NARROWED", "$.scope.targets", "target %r changed kind, locator or required layers" % t["id"])
    after_checks = {c["id"]: c for c in r["required_checks"]}
    for c in base["required_checks"]:
        if c["target"] in narrowed:
            continue
        a = after_checks.get(c["id"])
        if a is None:
            ctx.err("CHECK_DROPPED", "$.required_checks", "baseline check %r missing from retest" % c["id"])
        elif (a["target"], a["layer"]) != (c["target"], c["layer"]):
            ctx.err("CHECK_DROPPED", "$.required_checks", "check %r changed target or layer" % c["id"])
    linked = {f.get("baseline_finding_id") for f in r["findings"]}
    base_ids = {f["id"] for f in base["findings"]}
    for f in base["findings"]:
        if f["id"] not in linked and f["target"] not in narrowed:
            ctx.err("FINDING_DROPPED", "$.findings", "baseline finding %r has no retest entry" % f["id"])
    for i, f in enumerate(r["findings"]):
        b = f.get("baseline_finding_id")
        if b and b != "NEW" and b not in base_ids:
            ctx.err("BASELINE_MISMATCH", "$.findings[%d].baseline_finding_id" % i, "%r is not a baseline finding" % b)


def _check_secrets_and_public(ctx, public, host_policy):
    # The allowlist is reviewed code plus a separately reviewed host policy
    # (textscan.parse_host_policy). It is never derived from report content
    # such as sources[].url, and every applied override is reported.
    records = list(host_policy or [])
    default = frozenset(textscan.REVIEWED_PUBLIC_HOSTS)
    allowed = default | {r["host"] for r in records}
    suppressed = 0
    for path, text in _walk_strings(ctx.r):
        for name, _s, _e in textscan.find_secrets(text):
            ctx.err("RAW_SECRET", path, "secret-shaped value (%s); store location and type only" % name)
        if public:
            hits = textscan.find_public_leaks(text, allowed)
            for kind, _s, _e, _detail in hits:
                ctx.err("PUBLIC_LEAK", path, "%s; matched text withheld" % kind)
            if records:
                suppressed += len(textscan.find_public_leaks(text, default)) - len(hits)
    if public and records:
        ctx.warn("HOST_OVERRIDE_APPLIED", "--host-policy", "%d policy override(s); %d match(es) allowed; human sign-off required"
                 % (len(records), suppressed))
    if public:
        for i, e in enumerate(ctx.r["evidence"]):
            if e["redaction"] == "raw_local_only":
                ctx.err("PUBLIC_LEAK", "$.evidence[%d]" % i, "raw_local_only evidence cannot be published")


def _load_schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    bad = unsupported_schema_keywords(schema)
    if bad:
        raise ValueError("schema uses keywords this validator does not enforce: %s" % ", ".join(bad[:5]))
    return schema


def validate(report, baseline=None, public=False, host_policy=None):
    """host_policy: records from textscan.parse_host_policy (reviewed, never from the report)."""
    issues = []
    try:
        schema = _load_schema()
    except (OSError, ValueError) as exc:
        return [Issue("ERROR", "SCHEMA_UNAVAILABLE", "assets/report.schema.json", str(exc))]
    schema_check(report, schema, schema, "$", issues)
    if issues:
        return issues  # semantics need a well-formed document
    ctx = Ctx(report, issues)
    kind = report["report_kind"]
    base_ok = False
    if kind == "baseline":
        if report.get("baseline_audit_id"):
            ctx.err("REPORT_KIND_MIXING", "$.baseline_audit_id", "baseline reports do not reference another baseline")
        if baseline is not None:
            ctx.warn("BASELINE_IGNORED", "--baseline", "baseline reports are not compared against another report")
    else:
        if not report.get("baseline_audit_id"):
            ctx.err("REPORT_KIND_MIXING", "$.baseline_audit_id", "after-fix reports must name their baseline")
        elif report["baseline_audit_id"] == report["audit_id"]:
            ctx.err("REPORT_KIND_MIXING", "$.baseline_audit_id", "after-fix report must be a separate report")
        if baseline is None:
            ctx.err("BASELINE_REQUIRED", "--baseline", "after-fix reports must be validated against their baseline")
        elif not isinstance(baseline, dict):
            ctx.err("BASELINE_INVALID", "--baseline", "baseline must be a JSON object")
        elif baseline.get("report_kind") != "baseline":
            ctx.err("BASELINE_MISMATCH", "--baseline", "comparison file is not a baseline report")
        else:
            base_errors = sorted({i.code for i in validate(baseline) if i.level == "ERROR"})
            if base_errors:
                ctx.err("BASELINE_INVALID", "--baseline", "baseline fails validation (%s); fix it first"
                        % ", ".join(base_errors[:8]))
            else:
                base_ok = True
                ctx.current_from = _date(baseline["generated_on"])
    if ctx.generated is None:
        ctx.err("SCHEMA", "$.generated_on", "invalid date")
    for fn in (_check_ids_unique, _check_authorization, _check_scope, _check_evidence, _check_sources, _check_inventory_coverage,
               _check_checks, _check_findings, _check_reviews, _check_verdict):
        fn(ctx)
    if base_ok:
        _check_against_baseline(ctx, baseline)
    _check_secrets_and_public(ctx, public, host_policy)
    return issues


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate audit report structure (not truth).")
    ap.add_argument("report")
    ap.add_argument("--baseline", help="baseline report; required for after-fix reports")
    ap.add_argument("--public", action="store_true", help="also apply public-release leak rules")
    ap.add_argument("--host-policy", help="reviewed JSON host-override policy with rationale (with --public)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)
    try:
        report = load_json(args.report)
        baseline = load_json(args.baseline) if args.baseline else None
    except InputError as exc:
        print("ERROR INPUT: %s" % exc, file=sys.stderr)
        return 2
    if not isinstance(report, dict) or (args.baseline and not isinstance(baseline, dict)):
        print("ERROR INPUT: report and baseline must each be a JSON object", file=sys.stderr)
        return 2
    records = []
    if args.host_policy:
        if not args.public:
            print("ERROR INPUT: --host-policy only applies with --public", file=sys.stderr)
            return 2
        try:
            _hosts, records = textscan.parse_host_policy(load_json(args.host_policy))
        except (InputError, ValueError) as exc:
            print("ERROR INPUT: host policy rejected: %s" % safe_diagnostic(exc), file=sys.stderr)
            return 2
    issues = validate(report, baseline, args.public, records)
    errors = [i for i in issues if i.level == "ERROR"]
    status = "STRUCTURE_INVALID" if errors else "STRUCTURE_OK"
    if not args.public:
        public_scan = "not_run"
    else:
        public_scan = "matched" if any(i.code == "PUBLIC_LEAK" for i in errors) else (
            "needs_review" if records else "no_rule_matched")
    if args.json:
        print(json.dumps({"status": status, "verifies": "structure and internal consistency only",
                          "public_scan": public_scan, "host_overrides": textscan.policy_summaries(records),
                          "issues": [i.as_dict() for i in issues]},
                         indent=2, sort_keys=True))
    else:
        for i in issues:
            print(i)
        print("%s (%d error(s), %d warning(s)). Structure only; evidence authenticity is not verified."
              % (status, len(errors), len(issues) - len(errors)))
        for rec in textscan.policy_summaries(records):
            print("HOST_OVERRIDE %s: full policy stays local; human sign-off required" % rec["override_id"])
        if public_scan == "not_run":
            print("PUBLIC_SCAN_NOT_RUN: not checked for publication; rerun with --public before release review.")
        else:
            print("PUBLIC_SCAN: %s. Pattern rules only; a human approves publication." % public_scan.upper())
    return 1 if errors else (3 if args.public and records else 0)


if __name__ == "__main__":
    sys.exit(main())
