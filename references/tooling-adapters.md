# Tooling and adapters

The bundled scripts collect inventory and check report structure. They do not find vulnerabilities. Any scanner is an optional external tool that you install, pin and verify yourself. If a tool is missing, the check it serves is BLOCKED.

## Supply-chain rules for any external tool

- Pin an exact release, or a full commit SHA for CI actions. Never use a mutable tag such as `latest`, `main` or a moving major version.
- Verify the checksum or signature against the project's published values before first use.
- Run it read-only, against local checkouts or image tarballs where you can. Give it no production credentials.
- Record the tool name, version and verification method in the evidence summary or the `command_ref`.
- A familiar tool name is not a provenance check. Record the exact publisher, release and verification evidence rather than trusting a similarly named package or a mutable install command.

## Reviewed command matrix

These are example invocations, reviewed for read-only use. They are not bundled and not run automatically. Check each one against the tool's current documentation.

For commands that write evidence, `EVIDENCE_DIR` must be an approved owner-only directory outside the target checkout. Keep raw outputs there, inspect completion and error states, and redact them before any model or external handoff.

| Purpose | Command (example) | Layer | Notes |
| --- | --- | --- | --- |
| Inventory | `python3 scripts/inventory.py REPO --target ID --out inv.json` | source | Bundled. Never runs repository code. Not a scanner. |
| Report check | `python3 scripts/validate_report.py R.json [--baseline B.json] [--public]` | n/a | Bundled. Checks structure only. |
| Source dependencies | `osv-scanner scan source --recursive --no-resolve REPO` | dependency | [OSV-Scanner](https://github.com/google/osv-scanner), Apache-2.0. Start without dependency resolution; online query metadata and any later resolution need preflight approval. Check the installed version's offline/database flags when egress is prohibited. |
| Image packages | `osv-scanner scan image IMAGE@DIGEST` | image | Scan by digest, not by tag. |
| Filesystem | `trivy fs --scanners vuln,secret,misconfig --format json --output "$EVIDENCE_DIR/filesystem.json" REPO` | dependency / config | [Trivy](https://github.com/aquasecurity/trivy), Apache-2.0. Use an approved, restricted evidence directory outside the target. Redact before exporting any result. |
| Git history secrets | `gitleaks git REPO --redact=100 --report-format json --report-path "$EVIDENCE_DIR/history.json"` | credential | [Gitleaks](https://github.com/gitleaks/gitleaks). Record fetched-history coverage and reviewed suppression rules; a current-tree scan is not a history scan. |
| Image | `trivy image IMAGE@DIGEST` | image | Same pinning rules. |
| Agent configuration | Invoke the scan command from a separately installed, verified AgentShield release | process | [AgentShield](https://github.com/affaan-m/agentshield), MIT. Check that release's CLI help; never paste an unpinned `npx` install into an audit. Deep/active modes can execute hooks, and model-provider modes can export configuration, so neither is enabled by default. |
| Runtime facts | Owner-run, read-only query inside a running worker | runtime | No public diagnostic endpoints. A CLI binary is not proof of the SAPI runtime. |

Turning scanner output into evidence works like this:

- Interpret exit codes using the exact tool/version's documented contract and the retained output. A completed scan with findings is not an execution failure; a zero exit is not proof of complete coverage.
- Some scanners deliberately use a nonzero code for findings. Gitleaks documents code 1 for leaks or errors, so inspect its complete report and error stream, or configure and record a distinct findings code; never classify code 1 alone as either "vulnerable" or "blocked" ([Gitleaks command contract](https://github.com/gitleaks/gitleaks)).
- A crash, timeout or partial output gives `truncated`, `timeout` or `error` and makes the affected check BLOCKED. Record completed findings from other checks separately.
- Scanner advisories are leads until you confirm them against a primary source for the exact build.

## Related projects (concepts only)

- [ECC](https://github.com/affaan-m/ECC) (MIT): role handoffs, verification loops, evals and hooks. Its `plan-orchestrate` skill routes work without executing the emitted commands; multi-plan has a separate runtime prerequisite. Discover the actual host capabilities rather than assuming command parity.
- [Trail of Bits skills](https://github.com/trailofbits/skills) (CC-BY-SA-4.0): false-positive checking, insecure defaults, differential review and audit context building. This candidate uses workflow concepts and links, not bundled artifacts from that project; review its license before any future copying or adaptation.
- Other public audit pipelines exist, including post-patch validation workflows. This skill does not claim to be new or complete.

## Hooks and automation

This skill ships no hooks, no install scripts and no background jobs. If your platform supports hooks, treat any hook as code that runs with your privileges. Review it before enabling it, and keep it out of audit targets.
