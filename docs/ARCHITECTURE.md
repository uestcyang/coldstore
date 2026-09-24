# ARCHITECTURE

## Pager (pager/)
- `ws` — CLI. `index` builds the page table from workspace roots (a workspace is a directory with a
  `HANDOFF.md`; products, caches and venvs are explicitly non-workspaces). `page plan/sync/alerts/
  eviction-blocks` drive the tier state machine. `lint` forwards to `handoff_lint.py`.
- `workspace_pager.py` — page table schema, policy loader (schema v2, watermark ordering enforced),
  state machine HOT→WARM→COLD→cloud_only, liveness cache with TTL, auto-pin rules, alert codes.
- `workspace_pager_maintenance.py` — bounded ticks: archive drain, pressure loop, semantic
  annotation, all with per-tick budgets from policy.
- `workspace_pager_cycle.py` — cycle bookkeeping so a crashed tick can be resumed.
- `workspace_page_gate.py` — admission: a job may not write a page that is being archived/evicted.
- `workspace_consistency.py` — snapshot/inspect a tree; refuses symlink roots, broad roots, partial lines.
- `workspace_archive_remote.py` — ssh-side snapshot for the other host.
- `handoff_lint.py` — the HANDOFF.md contract linter that `ws` shares its predicates with.
- `pager_db_backup.py` — page-table backup with invariants check.

## Archive (archive/)
- `vault_v2_stream.py` — snapshot → tar → GPG AES256 symmetric → 1 GB shards → desktop-client stage
  dir → wait for the client's transmission.db to confirm → append ledger row. Single-writer locks.
- `vault_v2_versions.py` / `vault_v2_manifest.py` / `vault_v2_audit.py` — head pointers, per-root
  manifests, strict cloud audit (expected vs cached cloud blobs; zero tolerance).
- `logical_vault_v3.py` — sqlite logical vault over the shard ledger: objects, versions, events,
  stage/upload/decrypt with `key_path` injected (tests use a throwaway key).
- `cloud_asset_catalog.py` / `cloud_asset_find.py` — catalog of cloud assets with three-copy metadata.
- `cloud_asset_restore.py` — restore-verify: native download via DevTools, decrypt, tar, compare.
  Optional evidence, recorded when run; **not** an eviction prerequisite.
- `cloud_asset_evict_once.py` — the only deleter (`trust-the-cloud` contract: no download-back
  required). Gates: allowed prefix or registered workspace → version head match → cloud audit
  fresh → archive-time snapshot proof (metadata snapshot, or content fingerprint for legacy assets
  whose only proof is a historical restore test) → live source unchanged → full re-hash → no open
  handles / no process handles → delete → ledger both sides → post-conditions.
- `cloud_asset_delete_gate.py`, `cloud_blob_gc.py`, `baidu_client_delete.py` — cloud-side GC, also gated.
- `workspace_archive.py`, `workspace_pool_migrate_remote.py` — remote snapshot/migration helpers.

## Hosts
`host-a` (macOS) runs the desktop client and therefore every upload/download; `host-b` (Linux) holds
the managed pool and runs verification and eviction. Host identity is resolved by `platform.system()`
plus hostname folding; anything unknown lands in EXTERNAL and is never paged.
