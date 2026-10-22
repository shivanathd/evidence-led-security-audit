# Contributing

Contributions are welcome. Keep them small and testable.

## Ground rules

- **Synthetic audit data only.** Examples and tests use `service-a`, `*.example.invalid`, documentation IP ranges and made-up IDs. Never include real people, private organizations or repositories, internal domains, account IDs, incidents or audit findings. Reviewed citations to public vendor documentation and open-source projects are allowed.
- **Original work.** Do not copy prompts or code from other skill collections. This applies especially to share-alike licensed ones. If a project inspired your idea, link to it.
- **Standard library only** for scripts and tests. Do not add install hooks, network calls or background jobs.
- **Defensive scope.** No exploit payloads, no scanning recipes for third-party targets, no automatic remediation or publication.
- **Honest claims.** No "secure", "certified", "complete coverage" or similar wording, either in docs or in validator-accepted output.

## Before opening a pull request

```bash
python3 -B -m unittest discover -s tests
python3 scripts/check_public_package.py . --denylist /path/to/your/private-terms.txt
agentskills validate "$PWD"
```

If you change a validator rule, add a case to `tests/corpus/adversarial_cases.json` that the old rule would have let through.

If you change a dated profile, refresh its primary sources and update its "Last checked" date.

### Adding an incident profile

1. Copy an existing file in `profiles/` and name it `<topic>-<yyyy-mm-dd>.md`, using the disclosure date.
2. Cite primary sources only: the project or vendor advisory, the CVE record, the provider's own incident notice. News coverage can point you to them but is not cited.
3. Say what is unknown at the time of writing, and how a finding is closed under the skill's evidence rules.
4. Cited hosts must be on the reviewed list in `scripts/textscan.py` (`REVIEWED_PUBLIC_HOSTS`). Adding one is a reviewed code change.
5. Add a row to the profiles table in `README.md`. Never edit a profile into a "latest" list that is meant to stay current indefinitely. Add a new dated profile instead.
