# Optional profile: GMO Onamae Desktop Cloud unauthorized access of 2026-10-21

Last checked: 2026-10-28. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

The durable check class is **leaked credentials that were never revoked** in [references/scoped-checks.md](../references/scoped-checks.md). This file is a dated starting point for the GMO Internet Onamae Desktop Cloud incident. `scripts/host_checks.py` check id: `gmo-onamae-presence`. Inventory key: `gmo_onamae_hints`.

## Primary sources

- Vendor notice (twelfth report, 2026-10-27): [Current Response to Unauthorized Access to Onamae Desktop Cloud](https://internet.gmo/en/news/article/258/)
- For each credential you rotate: that provider's own documentation for revocation and audit logs

News coverage of a bounty figure can point you to the vendor notice. It is not a primary source for what data was taken.

## What was disclosed (as of the date above)

From the GMO Internet notice:

- Unauthorized access to **Onamae Desktop Cloud**, first reported 2026-10-21 (service suspended).
- The vendor confirmed that information believed to relate to customers has been **published** by the perpetrators (tenth report, 2026-10-27).
- The vendor is offering condolence payments for published categories (basic contact details; financial and authentication information; highly private information) and a cybercrime-bounty program. Those figures are vendor statements, not a data inventory.
- The vendor asked people not to access or spread published dumps, and warned about phishing that takes advantage of the incident.

Still record as UNKNOWN unless a later **vendor** source states them:

- a complete list of fields taken
- which named customer accounts were in the published set
- the entry point

## How this maps to the skill

This is a credential-exposure event (Phase 4) when Onamae Desktop Cloud, Onamae DNS or Onamae mail is in use. Detection is **local files only**. Do not query public DNS, do not contact the vendor, do not fetch WHOIS.

`scripts/inventory.py` and `gmo-onamae-presence` look for Onamae host strings in zone files, `named.conf` and DNS-ish configs. A generic mention of "GMO" is not a hit.

- `review` when a local file names an Onamae host (especially in NS / MX / nameserver context)
- `NOT_APPLICABLE` only when the **host walk** of that target found no Onamae host, with that empty result as evidence
- Empty `gmo_onamae_hints` from a repository inventory is not `NOT_APPLICABLE` without independent non-use evidence (owned-domain NS or registrar). Record that as `BLOCKED`

Targets to list in scope, linked with `related_targets`:

- each domain whose DNS or mail is hosted there (`saas_tenant`)
- the Desktop Cloud tenant (`saas_tenant`)
- repositories and servers that hold copies of those credentials (`repository`, `runtime`)

## Closing a credential finding

A finding is `fixed` only when all of these are captured:

1. **New credential issued** at every provider that shared a password, API token or registrar login with the Onamae account (never the value)
2. **Old value revoked** at those providers
3. **Misuse review** for the exposure window in registrar, mail, bank and DNS-change logs. No access to the logs makes this check BLOCKED, never "no misuse"

Do not treat "we do not use Desktop Cloud" as `NOT_APPLICABLE` if inventory still lists Onamae nameservers for an owned domain.

## Report wording

- Check title: `GMO Onamae Desktop Cloud / DNS use (customer-data breach)`.
- Finding summary: name the file class (zone, named.conf) without pasting NS hostnames into a public report. Use placeholders such as `ns1.example.com` and `example-host`.
- Absence: `NOT_APPLICABLE` only with a host-walk empty result. Empty inventory hints without owned-domain NS / registrar evidence are `BLOCKED`.
- Verdict: unchanged.

## What needs a human

Confirming whether an owned domain uses Onamae DNS or Desktop Cloud, rotating credentials, and reviewing published-data notices from the vendor.
