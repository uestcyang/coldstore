# PUBLIC_RELEASE_AUDIT — coldstore (release candidate v3, new repository object)

Status: **private candidate; not yet public**. Second-agent review required before visibility change.

## A. Repository
- Candidate: `uestcyang/coldstore-release` (private), a **new GitHub repository object** created for
  this candidate; the working tree was `git init`-ed fresh and pushed as a single initial commit.
  No remote, branch, tag or ref of any earlier private candidate is attached to this repository,
  and earlier candidate commit ids are deliberately not recorded here.
- Files in tree: 56.
- Verification commands for reviewers: `git log --all --oneline` (one commit), `git rev-list --objects --all`
  (only objects of that commit), GitHub `GET /repos/uestcyang/coldstore-release/commits` (one entry).

## B. Source → public mapping
| source (private snapshot) | public |
|---|---|
| workspace pager control (`ws`, `workspace_pager*.py`, `workspace_page_gate.py`, `workspace_consistency.py`, `archive_remote`, `pager_db_backup.py`, `handoff_lint.py`, `shared_context_policy.py` + 9 tests) | `pager/` |
| cold archive (`logical_vault_v3*.py`, `vault_v2_*.py`, `cloud_asset_*.py`, `cloud_blob_gc.py`, `baidu_client_*.py`, `workspace_archive.py`, shell helpers + test + 2 md) | `archive/` |
| deployment whitelists / policy | `config/*.example.json`, `config/archive.env.example` |

## C. Deleted (never entered the tree)
HANDOFF.md, SOURCE_STATE.txt, recovery reference manifest, `*.bak*`, cloud asset catalog (jsonl),
logical vault sqlite, vault ledger (tsv), secrets directory, cookies, any `.gpg`/`.key`, `__pycache__`.

## D. Parameterised
| real value | now |
|---|---|
| GPG passphrase path | `COLDSTORE_GPG_KEYFILE` env |
| desktop-client account directory hash | runtime glob discovery |
| cloud root | `COLDSTORE_CLOUD_BASE` (default `/ColdArchive`) |
| remote host / user | `COLDSTORE_REMOTE`, `host-a`/`host-b`, `user` |
| read-only engine roots, auto-pin roots, eviction prefixes | `config/pager_paths.example.json`, `archive.env.example` |
| users, hosts, IPs, project/engine/role names | deterministic tokens (`agent-a..k`, `engine-a..e`, `示例项目`) |
| dated incident narratives, operator order quotes, cloud task ids, restore dataset names, asset volumes | anonymised (`<date>`, `<time>`, `<task-id>`, `dataset-a/b/c`, `trust-the-cloud` policy) |

## E. Documentation / code consistency (eviction contract)
The code implements the `trust-the-cloud` eviction contract (`archive/cloud_asset_evict_once.py`,
`archive/logical_vault_v3_evict.py`, `pager/workspace_pager.py`): **no mandatory download-back
restore test before eviction**. Deletion requires the current cloud-confirmed head, archive-time
snapshot proof, live-source/snapshot consistency, current-version identity, metadata/audit gates,
path safety and open-handle/process safety gates. README, AGENTS.md, docs/ARCHITECTURE.md,
docs/LESSONS.md and docs/threat-model.md state exactly this and name the residual risk
(provider-side corruption after confirmation may go undetected until a later restore). An earlier
candidate's docs promised a per-eviction re-download; that promise was false and has been removed.

## F. Scan (run on both hosts and on the clean clone; see docs/privacy.md)
Release mode makes the out-of-tree deny wordlist mandatory (`--require-denylist` or
`COLDSTORE_RELEASE_SCAN=1`); a missing/unreadable denylist exits 2 and is never a PASS.
```
COLDSTORE_PRIVACY_DENYLIST=<outside-repo> python3 tools/public_privacy_scan.py --require-denylist .
PRIVACY_SCAN PASS findings=0 denylist=on mode=release
```
Generic rules: home paths, ssh targets, private/CGNAT/public IPs, ISO dates, 32-hex ids, emails,
CN mobile numbers, dispatch task ids, operator-quote markers, vendor cloud root, private keys, tokens.
Deny wordlist (real names) is kept outside the repository.

## G. Tests
| suite | result |
|---|---|
| pager (`python3 -m unittest discover`) | 213 run, OK (1 skipped) |
| archive | 10 run, OK |
| `ws --selftest` | 67 assertions, ok=True |
Run identically on macOS control host and Linux storage host.

## H. Residual exposure (deliberately listed; not "none")
- Cloud provider is named (Baidu desktop client, DevTools-driven transport).
- Algorithm design, gate ordering and directory conventions (`v2/<bucket>/<id>.blob`) are public.
- Incident narratives remain, anonymised; sequence and rough magnitudes ("~80GB", "18h") are visible.
- Third-party pin: `aurelio-labs/semantic-router` upstream commit and wheel sha256 (public package data).
- Two-host topology (macOS control + Linux GPU/storage) is described.
- Timing/size metadata of blobs is not hidden from the provider (docs/threat-model.md).
- Earlier private candidates of this tree existed under a different repository object for under one day;
  that repository stays private and is not referenced by this one.
- The cold tier is not a backup: after cloud confirmation, provider-side corruption is only caught by a later
  restore test or by replicated metadata making the loss describable (section E).
