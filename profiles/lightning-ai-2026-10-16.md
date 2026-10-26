# Optional profile: hosted AI/ML platform credentials of 2026-10-16

Last checked: 2026-10-26. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

The durable check class is **leaked credentials that were never revoked** in [references/scoped-checks.md](../references/scoped-checks.md). This file is a dated starting point for the Lightning AI Studio incident notice. Treat it as one vendor example of a broader class: hosted notebook and model platforms that store GitHub tokens, cloud keys and API keys.

## Primary sources

- Vendor incident notice: [October 2026 Security Incident](https://lightning.ai/security-incident/)
- For each credential you rotate: that provider's own documentation for revocation and audit logs.

If a later vendor page narrows scope, the later page wins. Do not fill gaps from social posts or secondary write-ups.

## What the vendor confirmed (as of the date above)

From the Lightning AI notice:

- On 15 October 2026, 23:00 UTC, Lightning identified unauthorized access to credentials on the Lightning Platform.
- On 16 October 2026, 01:00 UTC, Lightning revoked all user access to the Lightning Platform to address the issue.
- Affected services: Lightning Studio Platform services (Studio, Deployments, Pipelines, Drive).
- Not in that list: GPU cluster rental infrastructure, and managed services such as Kubernetes and SLURM.
- Lightning states it believes certain customer credentials were used to reach environments and connected third-party services, that identified credentials used in the incident were revoked, and that an independent external firm is assisting.
- Lightning asked **all** users, whether or not they were contacted, to rotate secrets, API keys and credentials stored in AI Studios (the notice names GitHub credentials as an example) and to update credentials used for third-party services reached from those virtual machines.
- Customers Lightning had identified as potentially affected had been notified. The notice says that if you have not received a notification, Lightning has not identified your environment as affected **based on the investigation to date**.

## What remains unconfirmed

Mark these UNKNOWN unless a later **vendor** source states them:

- the entry point
- a complete list of credential types or names that were read
- how many customers were affected
- whether source code, datasets or model weights were read
- whether every stored third-party token was in the set Lightning revoked

Do not treat "no email from the vendor" as proof that a workspace was outside the affected set when the vendor also asked every user to rotate.

## How this maps to the skill

This is a credential-exposure event (Phase 4), not a code vulnerability. After a vendor breach of a platform that stored provider keys, the finding is **rotate-and-verify-revoked**.

The same rule applies to other hosted notebook and model platforms in scope, including:

- Lightning AI Studio
- Google Colab
- Hugging Face Spaces and Hugging Face secrets
- Replicate
- similar hosted notebook, workspace or model-runner tenants that keep GitHub tokens, cloud keys or API keys

Keep the check generic. Inventory **names** of secrets and the platform that held them. Never values. Never test an old credential by using it.

Targets to list in scope, linked with `related_targets`:

- the hosted platform tenant (`saas_tenant`)
- each workspace, studio or space that held variables (`runtime` or `saas_tenant`)
- each upstream provider whose credentials were stored (`saas_tenant`): GitHub, cloud accounts, AI inference providers, container registries, databases
- repositories and CI systems that hold copies of the same values (`repository`, `ci`)

## Closing a credential finding

A credential finding is `fixed` only when all of these are captured:

1. **New credential issued** at the upstream provider, with a reference to the change (never the value).
2. **Old value revoked** at that provider. Removing the secret from the hosted platform, or the vendor saying it revoked *some* identified keys, does not close other keys you stored there.
3. **Running jobs pick up the new value** (redeploy, restart, or a new studio session), with runtime evidence after the rotation.
4. **Misuse review** for the exposure window in each provider's logs, or `BLOCKED` if you cannot get the logs.

Other rules:

- Deleting a notebook, space or studio does not revoke the token at GitHub or the cloud provider.
- A vendor "we revoked identified keys" statement is evidence for those identified keys only. Other stored secrets stay `open` until you rotate and revoke them.
- Never test whether an old credential still works by using it.

## Report wording

- Check title: `Leaked credential still not revoked` or `Credential rotation after a hosted-platform disclosure`.
- Finding summary: name the platform class (hosted notebook / model runner), the secret **type** (GitHub token, cloud key, API key), and which upstream provider still needs revocation evidence. Do not name a real account, space or studio.
- Verdict: unchanged. Missing log access is `BLOCKED` and keeps the run `INCOMPLETE`.

## What needs a human

Rotating and revoking every stored credential, reviewing provider logs, notifying partners, and deciding whether to keep using the platform.
