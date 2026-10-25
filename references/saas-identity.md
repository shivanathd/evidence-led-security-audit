# SaaS and identity checks

Identity problems are usually authorization problems that are hiding behind successful authentication.

## SSO is not per-user authorization

- SSO at a gateway shows who the caller is. It does not decide what that caller can do further down the stack. Check every privileged route, export, admin action and background job for a per-user or per-role permission check on the server side.
- Look for routes that only check that a session exists. Look for roles taken from client-supplied claims. Look for checks that run only in the UI.
- Look for service-to-service calls that act for a user but drop the user's identity, so that a shared service account does the work.

## Tokens

- **Audience.** A token minted for one API must be rejected by the others. Record the effective audience and issuer validation for each service. Do not rely on library defaults. Some SDK fixes only apply when audience validation or strict input validation is switched on. A patched version without that setting is not a closure.
- **Lifetime and scope.** Record how long access and refresh tokens last, which scopes they carry and how revocation works.
- **Storage.** Never collect live tokens as evidence. Record where they are stored and how they are protected.

## SaaS tenants

- Only assess the tenants listed in scope, and only with a read-only audit role that the owner granted.
- Typical required checks:
  - admin and owner role assignments
  - how SSO and MFA are enforced
  - personal access tokens and app passwords
  - third-party app grants and their scopes
  - audit log availability and retention
  - external sharing defaults
- An API answer of 403 makes the check BLOCKED. It does not mean the tenant is fine. If a credential may have been exposed, misuse cannot be ruled out without the audit log.
- Export settings through the provider's own admin export where you can. Record the export date and the role used.
- If the tenant is a host or console that stores **other providers'** keys (AI, payment, git, cloud), a disclosure that those stored values may have been read is a credential-exposure event for every name that was stored. Rotate and revoke at the upstream provider, not only inside the tenant. See Phase 4 and the Railway and LiteLLM profiles.

## Discriminating tests for authorization fixes

Each authorization fix needs three tests, all run with owner approval in a host-enforced isolated, disposable environment:

| Test | What it shows |
| --- | --- |
| Before/after | A user without the permission succeeds against the old build and is refused by the new one. |
| Valid use | A user with the permission still succeeds. |
| Negative | A token for the wrong audience, a token for another tenant, and a token without the role are all refused. |

## What needs a human

- Granting audit roles and confirming the tenant matches the scope.
- Confirming that revocation and rotation took effect on the provider side.
- Reviewing audit logs for misuse when an automated export is not available.
