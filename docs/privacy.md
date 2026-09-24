# Privacy gate for public releases

Lesson learned twice: **identifier substitution is not sanitization.** Replacing user names,
hosts and project names leaves behind the layer that actually identifies a deployment —
dated incident narratives, verbatim operator orders, cloud task ids, restore dataset names,
internal engine/model names, asset volumes, account-local directory hashes.

Rule: *if a string is only true on one machine or one team, it does not belong in the tree.*
Incidents are kept (they explain every gate) but anonymised: no dates, no names, no quotes.

## Gates (all must pass, run from a fresh clone, not the working directory)

| gate | check |
|---|---|
| A secrets | tokens / keys / passphrases = 0 |
| B identity | real users, home paths, ssh targets = 0 |
| C topology | private / CGNAT / public IPs, hostnames = 0 (RFC 5737 examples only) |
| D business | project, customer, student, phone, email, chat-app ids = 0 |
| E cloud metadata | account-local ids, real cloud roots, recovery manifests = 0 |
| F runtime files | db / ledger / jsonl / log / gpg / HANDOFF / SOURCE_STATE not in tree |
| G history | single commit, no inherited private history |
| H regression | all test suites pass after parameterisation |
| I clean clone | A–F re-run on `git clone` into a temp dir |

```sh
git clone <repo> /tmp/check && cd /tmp/check
COLDSTORE_PRIVACY_DENYLIST=/path/outside/repo/denylist.txt python3 tools/public_privacy_scan.py --require-denylist .   # release mode: denylist mandatory, missing -> exit 2
(cd pager && python3 -m unittest discover -p 'test_*.py')
(cd archive && python3 -m unittest discover -p 'test_*.py')
python3 pager/ws --selftest
```

The deny wordlist lives **outside** the repository: the real names must not enter the tree even
as patterns. If the variable is set and the file is unreadable, the scan refuses to run.

Every release ships a `PUBLIC_RELEASE_AUDIT.md` with the source→public mapping, deletion list,
parameterisation list, scan output, test counts and **residual risks** (never "none").
