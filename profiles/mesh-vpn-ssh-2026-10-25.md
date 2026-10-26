# Optional profile: mesh VPN SSH exposure of 2026-10-25

Last checked: 2026-10-26. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

The durable check class is **mesh VPN SSH and privileged forwarding** in [references/scoped-checks.md](../references/scoped-checks.md). This file is a dated starting point for the Tailworm research published on 2026-10-25. Per-OS commands are in [references/endpoint-fleet.md](../references/endpoint-fleet.md#mesh-vpn-ssh-and-privileged-forwarding).

## Primary sources

- Researcher report: [Tailworm](https://tailworm.com/) (Erica Windisch, Cyberdione Labs). Lab window 2026-10-22 to 2026-10-24 against Tailscale client **v1.104.2** and headscale **v0.29.5**.
- Vendor bulletins page: [Tailscale security bulletins](https://tailscale.com/security-bulletins). As of the date above this run found **no** Tailworm bulletin, **no** CVE identifier, and **no** fixed release. Do not invent a CVE, bulletin number or patched version.
- Tailscale SSH policy: [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh) and the [policy-file syntax](https://tailscale.com/docs/reference/syntax/policy-file) (`ssh` rules, `action` `accept`/`check`, `users`, `nodeAttrs`).
- Tailnet Lock: [Tailnet Lock](https://tailscale.com/docs/features/tailnet-lock).
- Client environment knob (source, not a user-facing doc): `TS_SSH_DISABLE_FORWARDING` in the Tailscale SSH server ([`ssh/tailssh/tailssh.go`](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)). It is not a documented admin setting. Record whether it is set; do not set it during an audit.

Public reporting of Tailscale's reply (Mike Shaver, vice president of engineering) said the company received the report, had already been reviewing the same areas, is working on fixes, and is **not** recommending that everyone disable Tailscale SSH. This run did not retrieve a durable vendor URL for that reply. Re-read Tailscale's own pages this run. News coverage can point you to them but is not a primary source.

## What was disclosed (as of the date above)

The report says Tailscale SSH identifies the **device**, not a password or key. A single policy rule decides whether that device may open a session. Findings T1–T3 claim that when port forwarding (including Unix-socket forwarding) is allowed, an ordinary session can make the root-level `tailscaled` process dial, replace or race privileged sockets on the target. The researcher describes this as converting one foothold into root on other nodes the policy can reach. The report is lab work on unmodified released software, not a claim of exploitation on real networks. Tailscale has not confirmed the specific technical claims one by one.

This run confirmed from the report and from Tailscale's pages:

- **No CVE, no bulletin, no fixed version** at last check.
- Hosted Tailscale SSH can turn forwarding off **per rule** (fields on the evaluated SSH action; the public policy syntax page does not document the JSON keys). headscale **v0.29.5** grants local and remote forwarding on every accepted SSH session; the report says that version has no policy switch to turn it off.
- `action: check` (check mode) gates session start. It does not, by itself, disable forwarding inside an established session.
- Tailnet Lock changes whether a stolen enrollment key can join a rogue node. It is not a fix for SSH forwarding.
- Restricting the SSH user to a non-root account is defense-in-depth only. The report says the forwarding findings operate from an unprivileged session.

Do not record a closed finding because a later client build exists unless a **primary** vendor source names that build as the fix.

## How this maps to the skill

This is a **config** and **runtime** check. An image that only *contains* a mesh client is a hint, not proof that SSH is enabled.

Targets to list in scope, linked with `related_targets`:

- each host or fleet that may run a mesh client (`runtime`)
- the control-plane or policy source (`saas_tenant` or `repository` for an exported policy file)
- a self-hosted coordinator such as headscale (`runtime`)

The same **check class** applies to similar overlays when they grant remote-shell or privileged forwarding between nodes (Headscale policy, ZeroTier, NetBird). If that overlay is absent on the target, the check is `NOT_APPLICABLE` for that overlay, with evidence.

## Inventory (read-only)

`scripts/inventory.py` emits `mesh_vpn_hints` when it sees a Tailscale / Headscale / ZeroTier / NetBird image, compose service, Dockerfile install, config path or exported `ssh` policy. It does not contact other nodes and it does not match the product name in a comment.

On a live host, collect only what the owner already runs. Never change settings. Never `ping`, `ssh` or otherwise contact a peer. Commands are in [endpoint-fleet.md](../references/endpoint-fleet.md#mesh-vpn-ssh-and-privileged-forwarding).

Record, using placeholders in any report:

- whether Tailscale SSH (or the overlay's equivalent) is enabled on **this** node
- whether ACL / policy `ssh` rules allow port forwarding, and any related `nodeAttrs` or a `TS_SSH_DISABLE_FORWARDING` environment value
- whether rules are broad (`autogroup:member` to a wide destination, `root` as a user) or use `action: check`
- whether Tailnet Lock is on
- client version and auto-update state
- counts of stale or duplicate nodes (do not copy hostnames, tailnet names, IPs or user emails)

## Closing a finding under this profile

There is no `vendor_patch` path until a primary source names a fixed build. Until then:

- `open` if SSH is enabled and forwarding is allowed (or unknown on headscale accept rules), or if a broad `ssh` rule remains
- `mitigated` if forwarding is disabled on every **effective** rule **and** forwarding is disabled in the loaded prefs, environment, or overlay equivalent on every SSH-enabled node **and** rules are per-pair, with evidence. `TS_SSH_DISABLE_FORWARDING` is the Tailscale environment knob; other overlays use their own prefs or flags. Check mode and Tailnet Lock alone are not `fixed`. Tailscale's default implicit SSH rule (`action: check`, `src: autogroup:member`, `dst: autogroup:self`, `users: autogroup:nonroot` + `root`) counts as a grant until the owner shows a live replacement, or confirms that removing `ssh` was intentional. One node's SSH-off / `RunSSH=false` state is a **runtime** observation for that node only; it does not close the shared policy
- `fixed` only after a vendor-published build is installed and observed, bound to the layers that target requires
- A file with no `ssh` key is `BLOCKED` / UNKNOWN unless the owner confirms it is the live policy and that removing `ssh` was intentional. Do not treat a missing `ssh` block as "no grant"

Never test the finding by forwarding a socket or connecting to another node.

## Report wording

- Check title: `Mesh VPN SSH and privileged forwarding` (add the layer and the overlay name).
- Finding summary: name the overlay, whether SSH is enabled, whether forwarding is allowed or unknown, whether rules are broad, lock and auto-update state, and the client version. Use `autogroup:member`, `tag:app` and `user@example.com` as examples. Never paste a real node name, tailnet name, IP or account id.
- A missing CLI or unparsed policy is `BLOCKED`, never "clean".
- Verdict: unchanged.

## What needs a human

Approving any policy or forwarding change, enabling Tailnet Lock, deleting a device at the control plane, and deciding whether to keep using Tailscale SSH.
