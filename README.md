# evidence-led-security-audit

[![tests](https://github.com/shivanathd/evidence-led-security-audit/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/shivanathd/evidence-led-security-audit/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [Agent Skill](https://agentskills.io) that turns "are we affected?" into an answer backed by evidence. It guides an AI agent (Claude Code, Codex, Cursor and others that read `SKILL.md`) through a read-only security audit of systems you are allowed to assess, and makes it report what it could not check instead of calling it clean.

It was written during the October 2026 PHP remote-code-execution release and the Railway environment-variable exposure, and works for any stack.

## Why

Agent-run security checks tend to fail in the same few ways:

- `php -v` on the CLI is taken as proof of what the web server runs.
- A scanner that never ran is reported as "0 findings".
- A fix merged in git is called done before the image is deployed.
- A leaked key is "fixed" by deleting it from the repo, without rotating or revoking it.
- One model role-playing three reviewers is presented as independent review.

This skill blocks each of these with explicit rules, and ships a validator that rejects reports that break them.

## Install

```bash
npx skills add shivanathd/evidence-led-security-audit
```

Install for Claude Code only, for all your projects:

```bash
npx skills add shivanathd/evidence-led-security-audit -a claude-code -g
```

Or clone the repository into your agent's skills directory (for Claude Code, `~/.claude/skills/`). Keep the folder name `evidence-led-security-audit`.

**Requirements:** Python 3.9 or newer, standard library only. Nothing to install, no network calls. The file helpers need macOS or Linux; on other hosts they stop with `BLOCKED` instead of running with weaker checks.

## Use it

Ask your agent in plain language and name what you own:

- *"Audit our api repo and its production image for the October 21 PHP RCEs. I own both. Read-only."*
- *"Our app ran on Railway. Work out which secrets were exposed and build the rotation and revocation checklist."*
- *"I manage our Macs, Linux servers and Windows laptops. Which of them still trust the compromised eMudhra intermediates? Read-only, through our MDM."*
- *"Here's the patched build. Retest it against last week's baseline report."*

The agent then:

1. Confirms authorization, scope and which human approves what.
2. Inventories the targets and runs checks layer by layer (source, dependency, image, runtime, identity, credentials, config). Each check ends as PASS, FAIL, BLOCKED, NOT_RUN or NOT_APPLICABLE, with evidence.
3. Writes a **baseline report** (JSON and Markdown) and a fix plan with retests and rollbacks.
4. After fixes ship, writes a separate **after-fix report** that the validator compares with the baseline.
5. Gives one of three verdicts. It never says "secure".

| Verdict | Meaning |
| --- | --- |
| `INCOMPLETE` | Something required was not checked, was blocked, or a fix is not verified on the running system |
| `ISSUES_OPEN` | Coverage is complete, but a finding is open, mitigated, accepted as risk, or fixed and not deployed |
| `CLEAR_WITHIN_COVERED_SCOPE` | Nothing open, for the listed targets and checks only |

How the verdict is decided:

```mermaid
flowchart LR
    A[Checks and findings recorded] --> B{Anything unchecked<br/>or unverified?}
    B -- yes --> I[INCOMPLETE]
    B -- no --> C{Anything failing<br/>or still open?}
    C -- yes --> O[ISSUES_OPEN]
    C -- no --> K[CLEAR_WITHIN_COVERED_SCOPE<br/>listed targets only]
```

## How it works

`SKILL.md` is a short hub. The agent loads the detail it needs from `references/`. Every phase ends with a gate; a failed gate stops the run or records the gap as BLOCKED, never as a pass.

```mermaid
flowchart TB
    subgraph assess["Assess (read-only)"]
        direction LR
        P0[0 Preflight] --> P1[1 Inventory] --> P2[2 Advisories] --> P3[3 Layered checks] --> P4[4 Credential exposure] --> P5[5 Refutation]
    end
    subgraph report["Report"]
        direction LR
        P6[6 Baseline report<br/>and fix plan] --> H(["People approve<br/>and deploy fixes"])
    end
    subgraph retest["Retest"]
        direction LR
        P7[7 After-fix retest<br/>against the baseline] --> P8[8 Postflight<br/>and verdict]
    end
    assess --> report --> retest
```

| Phase | What happens | Detail |
| --- | --- | --- |
| 0 Preflight | Authorization, scope, approver roles, tools | [phases.md](references/phases.md) |
| 1 Inventory | `scripts/inventory.py` lists manifests, listeners, hooks, secrets (location only) | [phases.md](references/phases.md) |
| 2 Advisories | Re-read primary sources this run, with dates | [profiles/](profiles/) |
| 3 Checks | One target and one layer per check | [scoped-checks.md](references/scoped-checks.md), [saas-identity.md](references/saas-identity.md), [endpoint-fleet.md](references/endpoint-fleet.md) |
| 4 Credential exposure | Owner, rotation, revocation, misuse review | [scoped-checks.md](references/scoped-checks.md) |
| 5 Refutation | Try to disprove every finding and every PASS | [orchestration.md](references/orchestration.md) |
| 6 Baseline report | Validate, then render | [reporting-release.md](references/reporting-release.md) |
| 7 After-fix retest | Separate report, validated against the baseline | [reporting-release.md](references/reporting-release.md) |
| 8 Postflight | Sanitize, check the package, state the gaps | [reporting-release.md](references/reporting-release.md) |

A fix only counts as closed when the fixed commit is the one the deployed image was built from, and that image digest is observed on the running service.

```mermaid
flowchart LR
    S[Fixed source commit] -->|must equal| D[Commit the deployed<br/>image was built from]
    D --> I[Image digest]
    I -->|observed on| R[Running service]
    R --> F([Finding can close])
```

A tag is not a digest, and `php -v` on the CLI says nothing about the web server's runtime.

## Endpoints and fleets

For laptops and servers, [endpoint-fleet.md](references/endpoint-fleet.md) gives read-only checks for macOS, Linux and Windows (OS build, installed packages, listening services, certificate trust stores, Java runtimes) and explains how to collect them at scale through an MDM, osquery or configuration management in check mode. Devices that don't report count as gaps, not as clean. The bundled Python helpers don't run on Windows, so Windows evidence is collected with PowerShell and checked elsewhere.

## Incident profiles

Profiles are dated starting points for specific incidents. They are not "latest" lists: the agent still re-reads the primary sources on every run, and a changed source wins.

| Profile | Covers | Last checked |
| --- | --- | --- |
| [php-2026-10-21.md](profiles/php-2026-10-21.md) | CVE-2026-109618 and CVE-2026-109619 (PHP RCE via OOM corruption and stale global state): fixed builds, exposure per SAPI, interim measures, closure evidence | 2026-10-22 |
| [railway-2026-10-21.md](profiles/railway-2026-10-21.md) | Possible exposure of environment variables stored on Railway: inventory, rotation, revocation and misuse review | 2026-10-22 |
| [emudhra-2026-10-17.md](profiles/emudhra-2026-10-17.md) | Compromised eMudhra intermediate CA keys: which clients and trust stores still accept the chains, per OS and runtime, and how to prove they no longer do | 2026-10-22 |

To add one, copy an existing profile, cite primary sources only, and name it `<topic>-<yyyy-mm-dd>.md`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Bundled scripts

The scripts check inventory and report consistency. They are not vulnerability scanners. Run these from the skill folder. `OUT` must be a canonical path, because the scripts refuse any path that contains a symlink. On macOS, `/tmp` and `/var` are symlinks, so resolve the path first:

```bash
OUT="$(cd "$(mktemp -d)" && pwd -P)"
```

<!-- tested-commands -->
```bash
python3 scripts/validate_report.py assets/examples/baseline-report.json
python3 scripts/validate_report.py assets/examples/after-fix-report.json --baseline assets/examples/baseline-report.json --public
python3 scripts/render_report.py assets/examples/baseline-report.json --out "$OUT/baseline.md"
python3 scripts/render_report.py assets/examples/after-fix-report.json --baseline assets/examples/baseline-report.json --out "$OUT/after-fix.md"
python3 scripts/inventory.py assets --target service-a-repo --out "$OUT/inventory.json"
python3 scripts/check_public_package.py .
python3 -B -m unittest discover -s tests
```

`tests/test_public_package.py` runs every `python3` line in this block, apart from the unittest line, against a clean copy of the package.

### What each script proves and does not prove

- **`inventory.py`** reads files and lists what it finds: manifests and lockfiles (nested, test-like and vendored ones marked), Dockerfiles, listeners, PHP runtime hints, install hooks, CI action pinning, agent instruction files, secret-shaped values and leftover artifacts.
  - It never executes repository code and never follows symlinks. It walks by directory handle, so a directory swapped mid-walk shows up as a coverage gap.
  - Secrets are reported by location only, never by value.
  - Symlinked, binary, special, oversized and excluded content (including `.git/`) makes coverage `PARTIAL`, and `--strict` exits 3. The only exception is content a human accepts with `--accept-exclusion 'PATTERN=REASON'`, which is recorded and still unscanned.
  - It knows nothing about images, running processes or CVEs.
- **`validate_report.py`** checks a report against the schema and consistency rules. Examples:
  - A PASS backed by blocked, truncated, stale or other-target evidence is rejected.
  - A missing required layer makes the verdict `INCOMPLETE`.
  - A "fixed" finding needs a before/after test or vendor-patch evidence, bound to the deployed image digest.
  - Accepted risk and undeployed fixes keep the verdict at `ISSUES_OPEN`.
  - After-fix reports need a valid `--baseline`.

  It cannot tell whether the evidence is real. `--public` adds leak rules and withholds the matched text. Without it, the validator prints `PUBLIC_SCAN_NOT_RUN`.
- **`render_report.py`** turns a valid report into Markdown, treating all report data as plain text. It redacts URL credentials, private-key blocks and token shapes, refuses reports that contain secret-shaped values, and never overwrites a file without `--force`.
- **`check_public_package.py`** looks for things that should not be published: secret-shaped strings, non-reserved hosts, emails, IP addresses, account-like IDs, home paths, hooks, symlinks and caches. Pass your own private terms with `--denylist` (keep that file outside the package). Extra public hosts come only from a reviewed `--host-policy` file, and any override returns `NEEDS_REVIEW`. A clean run means no rule matched; it does not prove the package is free of private data.

Host policy format (the same file works for `validate_report.py --public --host-policy`):

```json
{"approved_by_role": "publication approver",
 "hosts": [{"host": "docs.vendor.example", "rationale": "public vendor documentation cited in references"}]}
```

## Safety model

- **Read-only by default.** No exploit payloads, production probes, installs or running repository code. Active tests need owner approval and a host-enforced disposable environment.
- **People approve.** Scope, fixes, deploys, risk acceptance and publication each need a named human role. Agents draft and check; they never approve.
- **No secret values** in reports, prompts or tickets.
- **Instructions are not a sandbox.** The skill tells the agent what to do but cannot enforce it. See [SECURITY.md](SECURITY.md).

## Limits

- The machine-checked deployed-fix chain is image-based: source commit, build revision, image digest, runtime observation. For bare-metal or managed services, collect the real package and runtime evidence and report closure as incomplete; do not invent a digest to make validation pass.
- The required layers per target are a floor, not a full checklist. Add the checks the engagement needs before work starts.
- The validator enforces the inventory it is given. A reviewer still compares the report's inventory record with the raw inventory output.
- Tested on Linux and on macOS with Python 3.9 and 3.14. Windows is not supported by the file helpers. See [VALIDATION.md](VALIDATION.md).

## Repository layout

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Hub the agent loads first |
| `references/` | Phases and gates, layered checks, SaaS and identity, endpoints and fleets (macOS, Linux, Windows), orchestration, tooling, reporting |
| `profiles/` | Dated incident profiles |
| `assets/report.schema.json` | Report structure |
| `assets/examples/` | Synthetic baseline and after-fix reports (`service-a`, `example.invalid`) |
| `scripts/` | `inventory.py`, `validate_report.py`, `render_report.py`, `check_public_package.py` |
| `tests/` | Standard-library unit tests and an adversarial corpus of 69 bad reports |

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Report problems in the skill itself privately, as described in [SECURITY.md](SECURITY.md).

## Prior work

This is an original implementation. Ideas came from these public projects; no prompts or code were copied.

- [ECC](https://github.com/affaan-m/ECC) (MIT): role handoffs, verification loops, evals and hooks.
- [AgentShield](https://github.com/affaan-m/agentshield) (MIT): agent-configuration scanning and evidence bundles.
- [Trail of Bits skills](https://github.com/trailofbits/skills) (CC-BY-SA-4.0): false-positive checking, insecure defaults, differential review. Concepts only.
- [OSV-Scanner](https://github.com/google/osv-scanner) and [Trivy](https://github.com/aquasecurity/trivy): optional external scanners, not bundled.

Other end-to-end audit skills exist. This one does not claim to be new, complete or better.

## License

MIT. See [LICENSE](LICENSE).
