# coldstore — virtual memory for agent workspaces: a Pager with proof-gated eviction and an encrypted cloud cold tier

`coldstore` is the storage-tier control plane extracted from a two-host, multi-agent
production setup (a macOS control host + a Linux GPU/storage host). It answers one
question deterministically: **which directories may leave local disk, when, and what
evidence must exist before a single source byte is deleted.**

It is not a backup tool, not a sync tool, and not a cloud-drive client. It is a *pager*:
workspaces are pages, the local disk is RAM, a consumer cloud drive is swap, and every
transition is gated by fail-closed checks that were each added after a real incident
(see `docs/LESSONS.md`). The cloud adapter is one replaceable module; the parts with
identity are the page table, the liveness/eviction planner and the **proof-gated
eviction** chain that must pass before a single source byte is deleted.

```text
 ws (CLI)  ──index──▶  page table (sqlite)  ──plan──▶  HOT / WARM / COLD / PINNED
                              │                               │
                    liveness probe (find -newermt)      eviction candidates
                              │                               │
                     workspace_page_gate ◀── dispatcher ──▶ maintenance tick
                                                              │
                        archive layer: snapshot → GPG(AES256) → 1 GB shards
                        → desktop-client upload → cloud confirm (head + audit)
                        → live source == archive-time snapshot → full re-hash
                        → handle/path safety → only then delete source
```

## Two layers

| dir | what | runs on |
|---|---|---|
| `pager/` | `ws` CLI, page table, policy watermarks, liveness/consistency probes, eviction planner, maintenance ticks, HANDOFF lint, DB backup | both hosts |
| `archive/` | encrypted shard streamer, ledgers, versioned logical vault (sqlite), restore verifier, eviction executor with 8 gates, blob GC, delete gate | control host drives the desktop client; storage host runs verification |

The cloud transport is deliberately the vendor's **official desktop client driven over its
DevTools port** (`archive/baidu_client_download.py`). No cookies, no undocumented HTTP APIs,
no account keys in code. Swap that one module to target another provider.

## Guarantees the code enforces (not the docs)

- **Eviction contract ("trust-the-cloud").** Eviction does *not* require an immediate
  download-back restore test. A source may be deleted only when the current cloud-confirmed
  head, the archive-time snapshot proof, live-source/snapshot consistency, current-version
  identity, metadata/audit gates, path safety, and open-handle/process safety gates all pass.
  Any gate failing leaves the source. Restore verification (`archive/cloud_asset_restore.py`)
  remains available and may be recorded, but it is not a mandatory prerequisite for every
  eviction. **Residual risk:** provider-side corruption that happens *after* cloud confirmation
  may remain undetected until a later restore, unless another independent copy or verification
  mechanism catches it earlier (see `docs/threat-model.md`).
- **Empty evidence is refusal.** A probe that cannot run returns `None`, and `None` is never
  interpreted as "cold". ssh failure cannot manufacture cold evidence.
- **Pin lists only protect.** Config unreadable ⇒ empty pin list, never a widened one.
- **Policy is required.** No `workspace_pager_policy.json` ⇒ `REFUSE_PAGER_POLICY_UNREADABLE`, not defaults.
- **One grace clock.** `pressure_waiting()` and `eviction_candidates()` share it (a mismatch
  once hid a 79 GB asset for 18 h — LESSONS §3).

## Quick start

```bash
mkdir -p ~/.coldstore/etc
cp config/workspace_pager_policy.example.json ~/.coldstore/etc/workspace_pager_policy.json
cp config/pager_paths.example.json           ~/.coldstore/pager_paths.json
cp config/archive.env.example                ~/.coldstore/archive.env && $EDITOR ~/.coldstore/archive.env
source ~/.coldstore/archive.env
python3 pager/ws index --rebuild        # build the page table
python3 pager/ws page plan --json       # what would move, and why not
python3 pager/ws page alerts            # machine-readable alert list for a dashboard/widget
```

Tests (no network, no cloud, no GPG key needed):

```bash
(cd pager   && python3 -m unittest discover -s . -p 'test_*.py')   # 213 tests
(cd archive && python3 -m unittest discover -s . -p 'test_*.py')   # 10 tests
python3 pager/ws selftest
```

## Configuration surface

Everything deployment-specific is external. See `config/`:

- `workspace_pager_policy.example.json` — watermarks, mounts, budgets (schema v2, validated on load).
- `pager_paths.example.json` — read-only engine roots and auto-pin roots.
- `archive.env.example` — `COLDSTORE_GPG_KEYFILE`, `COLDSTORE_CLOUD_BASE`, `COLDSTORE_REMOTE`, allowed eviction prefixes.

Resolution order is always `env var → ~/.coldstore/... → repo config/*.example`.

## Status

Extracted from a production system. Host names, users, project, engine and role names were
replaced deterministically (`host-a`/`host-b`, `agent-a..j`, `engine-a..e`); incident
narratives in comments are kept but anonymised (no dates, names or quotes). Release gates and
the privacy scanner are in `docs/privacy.md`; residual exposure is listed in
`PUBLIC_RELEASE_AUDIT.md`. See `AGENTS.md` if you are an agent operating this repo.
