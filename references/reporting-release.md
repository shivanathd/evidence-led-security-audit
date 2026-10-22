# Reporting and release

## Two reports, never one

- **Baseline** (`report_kind: baseline`): records the state before any fix. It contains no `fixed` findings and no fix evidence. It includes a fix plan or an evidence plan for every open, mitigated or unknown finding.
- **After-fix** (`report_kind: after_fix`): a separate report with its own `audit_id` and a `baseline_audit_id`. Validate it with `--baseline`. The baseline must exist, must be a JSON object and must itself pass validation. If any of those is missing, the result is an error, not a warning.
- The baseline is a historical record. In an after-fix report, any evidence used to support PASS, fixed or refuted must have been collected on or after the baseline date. The baseline's own findings are not evidence of the current state.

## Required-check matrix

Each repository target also needs an `inventory_coverage` record linked to its captured inventory evidence. PARTIAL, BLOCKED, NOT_RUN or any UNACCEPTED gap forces INCOMPLETE even if all supplied checks say PASS. Exclusions require `APPROVED_OUT_OF_SCOPE`, a reason, a human approver role and an approval reference; the validator cannot authenticate that approval or discover deliberately omitted evidence, so a reviewer must compare the record with the retained raw inventory.

Each authorized target needs at least one required check for each layer its kind requires. A target's `required_layers` can add layers. Nothing can remove them.

| Target kind | Minimum layers |
| --- | --- |
| repository | dependency, credential, config |
| image | image |
| runtime | runtime, config |
| saas_tenant | identity, config |
| ci | process, credential |
| agent_config | process |
| other | at least one check |

Rules for the matrix:

- A gap in the matrix makes the report INCOMPLETE.
- NOT_APPLICABLE needs a reason, same-target evidence and a human `approved_by_role`.
- A dependency PASS must cover exactly the inventoried manifests for its target. If the target has no inventoried manifests, it cannot pass.

## Evidence binding

- Check evidence must come from the check's own target.
- Finding evidence must come from the finding's target, or from a target it names in `related_targets` (an owner-declared link such as built-from, deployed-as or credential provider).
- Human attestations record context and approvals. They never prove technical execution, runtime state, deployment or a fix.
- A deployed fix needs this chain, with every link recorded:

```text
source_sha (fixed commit)
  == deployed_source_sha (commit the deployed image was built from)
  -> image_digest of the deployed image (image or runtime evidence carrying both)
  -> runtime-layer evidence observing that digest on the running service
```

A source SHA is not an image digest. An image tag is not a digest.

## Closure paths for `fixed`

| `verification_basis` | Required |
| --- | --- |
| `behavior_test` | The same security test fails on the old artifact and passes on the new one. Valid-use and negative tests pass. Active tests require host-enforced disposable isolation as well as owner approval; approval alone is not isolation. |
| `vendor_patch` | `package` and `fixed_build`. Package-advisory evidence for that exact package and build, linked to a primary advisory. Captured evidence that the build is installed on the target, inside the deployed digest. Application regression tests. No exploit reproduction is needed. |
| `not_execution_verified` | The reason the baseline test could not be run safely. The verdict stays INCOMPLETE. |

Other rules for fixed findings:

- **Configuration-dependent fixes** need effective-configuration evidence.
- **Credential findings** need captured rotation and revocation evidence.
- **Undeployed fixes** keep the finding open. The one exception is a test-only or dev-only component in a repository, CI or agent-config target, where image or runtime evidence shows the component is excluded.
- **Mitigations** are reported as `mitigated` and are never treated as fixes.
- **Accepted risk** keeps the verdict at ISSUES_OPEN.

## Verdicts

- `INCOMPLETE` applies when any of these is true:
  - the matrix has a gap
  - a check is BLOCKED or NOT_RUN
  - a finding is unknown
  - a fix is `not_execution_verified`
- `ISSUES_OPEN` applies when coverage is complete and any of these is true:
  - a check is FAIL
  - a finding is open, mitigated or accepted risk
  - a deployment-relevant fix is undeployed
- `CLEAR_WITHIN_COVERED_SCOPE` applies otherwise. It covers only the listed targets and checks.

Primary sources older than seven days cannot support a clearing claim. Neither can evidence older than 30 days. Refresh them, or leave the item open.

## Sanitization and release

1. Redact secrets before any handoff. Keep raw output local, with restricted access and a set retention period.
2. Keep diagnostics value-free. Report the category and the JSON path or file line, never the matched host, address or term.
3. Run `validate_report.py --public`. The public allowlist has two parts: reviewed code (`textscan.REVIEWED_PUBLIC_HOSTS`), and an optional `--host-policy` file that names a human approver role and gives a rationale for each exact host. Overrides are reported through opaque IDs and counts, not their hostnames, roles or rationale. They produce public status `NEEDS_REVIEW` and exit 3 even if the report is structurally valid; a role string is not authenticated approval.
4. Run `check_public_package.py DIR --denylist LOCAL_FILE`. Keep the denylist local and any host policy outside the package under review. Binary content or applied host overrides produce `NEEDS_REVIEW` (exit 3), never automatic release approval.
5. Get approval from the named publication role.

`STRUCTURE_OK` means the report is consistent. It does not mean the report is safe to publish. Without `--public` the validator prints `PUBLIC_SCAN_NOT_RUN`. A clean public scan means no pattern rule matched. It is not proof that the report is free of private data.
