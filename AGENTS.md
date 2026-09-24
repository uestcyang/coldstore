# AGENTS.md — operating contract for agents working in this repo

You are probably here to (a) run the pager, (b) add a gate, or (c) port the cloud adapter.
Read this before touching anything.

## Invariants you must not weaken
1. `None` from any probe means *unknown*, never *cold*. Grep for `fail-closed` before editing a probe.
2. A source directory is deleted only by `archive/cloud_asset_evict_once.py` after every gate passes.
   The contract is `trust-the-cloud`: cloud-confirmed head + snapshot proof + live re-hash + safety gates;
   a download-back restore test is recorded evidence, not a delete prerequisite. Do not document it otherwise.
   Do not add a second deletion path. Do not add `--force`.
3. Pin lists (`config/pager_paths*.json`) can only be extended by config, never by code edits.
4. `workspace_pager.load_policy()` refuses missing/invalid policy. Do not add silent defaults.
5. `pressure_waiting()` and `eviction_candidates()` in `pager/workspace_pager.py` must agree on the
   grace window. There is a test for it; keep it green.

## Where things are
- Page table: `~/.coldstore/state/workspace_pages.db` (sqlite). Back up with `pager/pager_db_backup.py`.
- Policy: `$COLDSTORE_PAGER_POLICY` → `~/.coldstore/etc/workspace_pager_policy.json` → `config/*.example.json`.
- Archive workspace (ledgers, vault sqlite, shards): `$COLDSTORE_ARCHIVE_WS` (default `~/.coldstore/archive`).
- GPG passphrase file: `$COLDSTORE_GPG_KEYFILE`. Never commit it. Never print it.
- Cloud adapter: `archive/baidu_client_download.py` (DevTools-driven desktop client). Port here for other providers.
- Pager bin resolution for archive modules: `$COLDSTORE_BIN` → `~/.coldstore/bin` (if it has `ws`) → sibling `pager/`.

## How to verify a change
```bash
(cd pager   && python3 -m unittest discover -s . -p 'test_*.py')
(cd archive && python3 -m unittest discover -s . -p 'test_*.py')
python3 pager/ws selftest
```
A change that needs the cloud to be tested is not finished; add a fixture.

## Naming in this snapshot
`host-a` = control host (macOS, runs the desktop client). `host-b` = storage/GPU host (Linux, mounts
`/` as managed pool and `/data` as isolation mount). `agent-a..j` are role names. `engine-a..e` are
read-only model/engine roots that must never be paged out (they are read, not written, so mtime
liveness alone would evict them — LESSONS §2). `app-a` is the mobile app workspace the lint knows about.
