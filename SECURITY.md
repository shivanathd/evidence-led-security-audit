# Security policy

## Reporting a problem in this skill

Use GitHub's private vulnerability reporting for this repository (the **Security** tab, then **Report a vulnerability**). Do not open a public issue. If that button is missing, open an issue that asks for a private channel and leave out the details. Leave out real secrets, hostnames and audit data. A synthetic reproduction built with `example.invalid` and `service-a` is enough.

These count as in scope:

- A script that executes target code, follows symlinks, overwrites files without `--force`, or prints a secret value.
- A validator rule that accepts a clear or fixed claim it should reject.
- Renderer output that can carry live markup or terminal escape sequences.
- Package checks that miss a whole category of leak.

## Safety boundaries of the skill itself

- The instructions in this skill are not a sandbox. They tell an agent what to do, but they cannot enforce it. Any active test of untrusted code must run in an isolated, disposable environment that the host enforces:
  - no production credentials
  - no network egress by default
  - thrown away after use

  If no such environment exists, record the check as BLOCKED.
- The bundled scripts use only the standard library. They make no network calls, run no subprocesses against the target and need no installation.
- Treat optional external scanners and adapters as third-party code. Pin and verify them before use (see `references/tooling-adapters.md`).
- Store raw evidence locally, restrict access to it and keep it only as long as needed. Redact it before it reaches a model, a ticket or a report.

## Supported versions

Only the latest released version gets fixes.
