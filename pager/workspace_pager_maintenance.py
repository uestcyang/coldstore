#!/usr/bin/env python3
"""Bounded maintenance and lightweight pressure passes for Workspace Pager.

The full pass reconciles the graph, drains the archive queue, and runs the
same bounded watermark gate as ``--pressure-only``.  Deletion remains impossible
until the physical migration is COMPLETE, policy explicitly enables it, a watermark
or a live capacity request needs space, and a cloud-confirmed, snapshot-proven
WARM candidate exists.

Operator policy "trust-the-cloud": the
restore-verification drain (download-back-before-evict) is retired.  A page
becomes evictable once its current archive head is cloud-confirmed and the local
tree still matches the archive-time snapshot; the executor never downloads.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN))
import workspace_pager as pager  # noqa: E402

WS = BIN / "ws"
DEFAULT_POLICY = Path.home() / ".coldstore/etc/workspace_pager_policy.json"
STATE_LOG = Path.home() / ".coldstore/state/workspace_pager_maintenance.jsonl"
EVICT_TOOL = pager.CLOUD_WORKSPACE / "cloud_asset_evict_once.py"
# Logical Vault v3 batches carry their proofs in logical_vault_v3.sqlite3, not in
# the fixed-1GB v2 ledger; they must be evicted by the v3 executor.  Routing is
# by registration in the v3 control plane, never by name alone.
V3_ASSET_RE = re.compile(r"^hostb-asset-pool-v3-(batch-[0-9]{4})$")
V3_DB = pager.CLOUD_WORKSPACE / "logical_vault_v3.sqlite3"
V3_EVICT_TOOL = pager.CLOUD_WORKSPACE / "logical_vault_v3_evict.py"
# Flag telling the v3 migration uploader (logical_vault_v3.py upload) to hand the
# single Baidu writer back to the pager at its next window boundary.
PAGER_PRIORITY_FLAG = pager.CLOUD_WORKSPACE / ".pager_priority"
WATCHER_TOOL = pager.CLOUD_WORKSPACE / "baidu_watcher.py"
ARCHIVE_LOCK = Path.home() / ".coldstore/state/workspace_pager_archive.lock"
# Refusals raised by the archiver's consistency/snapshot gates that do not change
# between passes.  <date> root cause (agent-a+agent-d): the full pass always archived
# plan()[0]; /home/user/sim-env (leveldb cache inside a venv) was refused on <date>
# at three separate times, so every pass burned its single archive slot on it and zero
# pages reached Baidu while ARCHIVE_CANDIDATE grew 767 -> 821.  Such pages go to the
# pager's archive-block ledger (``ws page archive-blocks``) and are skipped for
# ``archive_block_days``.
DETERMINISTIC_ARCHIVE_REFUSALS = (
    "REFUSE_REMOTE_CONSISTENCY", "REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT",
    "REFUSE_GIT_PARTIAL_ROOT", "REFUSE_MISSING_OR_SYMLINK_ROOT", "REFUSE_PAGE_UNKNOWN",
    "REFUSE_INVALID_TARGET", "REFUSE_PAGE_ARCHIVE_ASSET_AMBIGUOUS",
    "REFUSE_PAGE_WORKSPACE_NOT_FOUND", "REFUSE_PAGE_TARGET_AMBIGUOUS",
)
# These gates can recover as the owning task settles. Preserve the refusal,
# retry hourly, and release the writer to other queues in the meantime.
RETRYABLE_ARCHIVE_REFUSALS = (
    "REFUSE_GIT_DIRTY", "REFUSE_SQLITE", "REFUSE_SNAPSHOT_DRIFT",
    "REFUSE_PAGE_TREE_LIVE", "REFUSE_PAGE_LIVENESS_UNKNOWN",
)
# "Someone else is writing to the Baidu staging folder right now".  The Baidu
# folder-backup watcher drops create events when several files land within seconds
# (measured <date>: 3x178MB staged together ran 11.7x slower than serial and the
# third file never registered), so the folder is single-writer by contract: stop the
# drain and let the next tick retry instead of queueing more files behind it.
TRANSIENT_STOP_REFUSALS = (
    "REFUSE_WORKSPACE_ARCHIVER_BUSY", "REFUSE_VAULT_WRITER_BUSY", "REFUSE_STAGE_FOLDER_BUSY",
)
VAULT_WRITER_PATTERNS = (
    "[v]ault_v2_stream.py", "[l]ogical_vault_v3.py upload", "[w]orkspace_archive.py",
)
FOUNDRY_ARTIFACTS = (
    "function_foundry_index.jsonl", "function_foundry_storage.json",
    "capability_cards.jsonl", "capability_index.sqlite3",
    "capability_index_meta.json", "capability_router_manifest.json",
)
CAPABILITY_ROUTER_ENGINE = "aurelio-labs/semantic-router"
CAPABILITY_ROUTER_PACKAGE_VERSION = "0.1.16"
CAPABILITY_ROUTER_SOURCE_COMMIT = "8a7b5547e0a58e63b81fce5acceadf2a986275e9"
CAPABILITY_ROUTER_WHEEL_SHA256 = "b09a0cda7cbf60ad2dad677ed65c0974e816ea5494a49f33ab06316eab92bcf5"
CAPABILITY_ROUTER_LITELLM_FLOOR = "1.83.7"
CAPABILITY_ROUTER_LITELLM_VERSION = "1.98.0"
CAPABILITY_ROUTER_SCORE_THRESHOLD = 0.55
CAPABILITY_ROUTER_AGGREGATION = "max"
CAPABILITY_RETRIEVAL_CONTRACT_VERSION = 3


def call(args, timeout):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def policy(path):
    raw = pager.load_policy(path)
    if not isinstance(raw.get("evict_enabled"), bool):
        raise RuntimeError("REFUSE_AUTOMATIC_EVICTION_POLICY_TYPE")
    limit = raw.get("max_evictions_per_run")
    if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 256):
        raise RuntimeError("REFUSE_AUTOMATIC_EVICTION_LIMIT")
    return raw


def append_receipt(receipt):
    STATE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with STATE_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")


def evict_tool_for(asset_id, *, v3_db=None, v3_tool=None, v2_tool=None):
    """Pick the executor that owns this asset's proofs (fail-closed on ambiguity)."""
    v3_db = V3_DB if v3_db is None else Path(v3_db)
    v3_tool = V3_EVICT_TOOL if v3_tool is None else Path(v3_tool)
    v2_tool = EVICT_TOOL if v2_tool is None else Path(v2_tool)
    match = V3_ASSET_RE.match(str(asset_id or ""))
    if not match or not v3_db.is_file():
        return v2_tool
    with sqlite3.connect("file:%s?mode=ro" % v3_db, uri=True) as conn:
        registered = conn.execute(
            "SELECT 1 FROM batches WHERE batch_id=?", (match.group(1),)
        ).fetchone() is not None
    if not registered:
        return v2_tool
    if not v3_tool.is_file():
        raise RuntimeError("REFUSE_V3_EVICT_TOOL_MISSING asset=%s" % asset_id)
    return v3_tool


def vault_writer_busy(runner=call):
    """First live Baidu-staging writer (v2 stream / v3 upload / archiver), or None.

    Delegates to vault_v2_stream.vault_writer_busy (flock probe first, then a
    pgrep filtered to real python processes).  <date>: a bare ``pgrep -f``
    matched an agent's zsh wrapper whose command text mentioned the script name
    and the very first drain reported WAIT_VAULT_WRITER_BUSY with nothing running.
    """
    workspace = str(pager.CLOUD_WORKSPACE)
    if workspace not in sys.path:
        sys.path.insert(0, workspace)
    try:
        from vault_v2_stream import vault_writer_busy as _busy  # noqa: WPS433
    except Exception as exc:  # fail closed: treat an unimportable detector as busy
        return f"WRITER_DETECTOR_UNAVAILABLE {exc}"[:300]
    return _busy()


def publish_pager_priority(pg, archive_report, *, flag=None, allow_clear=True, clock=time.time):
    """Tell the v3 migration uploader to yield the Baidu writer while the pager needs it.

    <date>: batch-0001's v3 re-upload held .logical_vault_v3.lock for hours
    while the managed pool sat at 6.7% free; every archive tick reported
    WAIT_VAULT_WRITER_BUSY and nothing could become evictable.  The pager owns
    the writer whenever the pool is under pressure or it has admissible archive
    work; the migration is a repack of data that is already cloud-confirmed and
    can wait.  The flag is written atomically; cleared only by an archive tick
    that observed both conditions false (``allow_clear``).
    """
    flag = PAGER_PRIORITY_FLAG if flag is None else Path(flag)
    pool = pg.pool_status()["managed"]
    queue = int((archive_report or {}).get("remaining_queue",
                (archive_report or {}).get("queue", 0)) or 0)
    eviction_active = bool(pool.get("eviction_active"))
    active = eviction_active or queue > 0
    stamp = clock()
    decision = {"active": active, "eviction_active": eviction_active,
                "free_ratio": pool.get("free_ratio"), "archive_queue": queue,
                "ts": stamp, "expires_at": stamp + 1800, "flag": str(flag)}
    if active:
        tmp = flag.with_name(flag.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(decision, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, flag)
        decision["written"] = True
    elif allow_clear:
        flag.unlink(missing_ok=True)
        decision["cleared"] = True
    return decision


@contextlib.contextmanager
def archive_lock(path=None):
    """Non-blocking process lock shared by the full pass and the --archive-only tick."""
    path = ARCHIVE_LOCK if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def archive_budget(cfg, key, default):
    raw = cfg.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise RuntimeError(f"REFUSE_ARCHIVE_BUDGET {key}={raw!r}")
    return raw


def seed_items(cfg, pg):
    seeds = []
    for path in cfg.get("seed_paths", []):
        rows = pg.status(path)["rows"]
        if len(rows) == 1 and (not rows[0]["cloud_verified"] or
                               not rows[0]["snapshot_verified"] or rows[0]["dirty"]):
            seeds.append({"path": path, "workspace_key": rows[0]["workspace_key"],
                          "seed": True})
    return seeds


def archive_queue(pg, plan, seeds, blocked):
    queue = list(seeds) + [
        x for x in plan if x["action"] in {"ARCHIVE_CANDIDATE", "REARCHIVE_REQUIRED"}
    ]
    # Keep the first record (explicit seeds retain their zero-cooldown contract).
    unique = {}
    for item in queue:
        if item["workspace_key"] not in blocked:
            unique.setdefault(item["workspace_key"], item)
    return list(unique.values())


def retryable_archive_refusal(reason):
    """Classify the leaf code, not the remote transport wrapper or a filename."""
    for line in reason.splitlines():
        leaf = line.strip()
        while re.match(r"REFUSE_(?:PAGE_ARCHIVE|REMOTE_CONSISTENCY) rc=\d+ detail=", leaf):
            leaf = re.sub(r"^REFUSE_(?:PAGE_ARCHIVE|REMOTE_CONSISTENCY) rc=\d+ detail=", "", leaf, count=1)
        match = re.match(r"(REFUSE_[A-Z0-9_]+)(?:\s|$)", leaf)
        if match and any(match[1] == code or
                         (code == "REFUSE_SQLITE" and match[1].startswith(code + "_"))
                         for code in RETRYABLE_ARCHIVE_REFUSALS):
            return True
    return False


def live_archive_deferral(reason):
    return re.fullmatch(
        r"REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_PAGE_TREE_LIVE "
        r"host=\S+ path=.+ window_days=\d+(?:\.\d+)?", reason.strip()) is not None


def archive_drain(cfg, pg, plan, seeds, *, shadow, budget_sec, max_items,
                  runner=call, busy=vault_writer_busy, clock=time.time):
    """Serially archive queued pages until the item limit or time budget is hit.

    Replaces the <date>..<date> "one archive per 8h full pass" step.  Contract:
    * seeds first, then plan ARCHIVE_CANDIDATE/REARCHIVE_REQUIRED in plan order;
    * pages in the archive-block ledger are skipped;
    * one page at a time, never while another Baidu-staging writer is alive
      (single-writer folder contract, see TRANSIENT_STOP_REFUSALS);
    * a deterministic REFUSE_* records a block and the drain moves on;
    * a folder-busy refusal / timeout ends this round without blocking the page.
    """
    mode = "shadow" if shadow else cfg["archive_mode"]
    blocked = (pg.archive_blocks(float(cfg.get("archive_block_days", 7)))
               if hasattr(pg, "archive_blocks") else {})
    candidates = archive_queue(pg, plan, seeds, {})
    blocked_candidates = [blocked[x["workspace_key"]] for x in candidates
                          if x["workspace_key"] in blocked]
    deferred_candidates = sum(live_archive_deferral(x.get("reason", ""))
                              for x in blocked_candidates)
    queue = archive_queue(pg, plan, seeds, blocked)
    under_pressure = bool(pg.pool_status()['managed']['eviction_active'])
    if under_pressure:
        # Uploads have the same fixed per-page overhead as eviction. Keep
        # explicit seeds first, then free the largest admitted pages soonest.
        seed_keys = {x['workspace_key'] for x in seeds}
        queue = ([x for x in queue if x['workspace_key'] in seed_keys]
                 + pressure_order([x for x in queue if x['workspace_key'] not in seed_keys]))
    report = {"status": None, "mode": mode, "queue": len(queue),
              "order": "largest_first" if under_pressure else "plan_order",
              "remaining_queue": len(queue), "retry_queue": 0,
              "blocked_before": len(blocked), "budget_sec": budget_sec,
              "blocked_candidates": len(blocked_candidates) - deferred_candidates,
              "deferred_candidates": deferred_candidates,
              "max_items": max_items, "attempts": [], "archived": 0, "blocked": 0,
              "skipped": 0, "live_deferred": 0}
    if not queue:
        report["status"] = ("BLOCKED_PENDING" if report["blocked_candidates"] else
                            "LIVE_DEFERRED" if deferred_candidates else "IDLE")
        return report
    if not max_items:
        report["status"] = "DISABLED"
        report["remaining_queue"] = 0
        return report
    started = clock()
    for item in queue:
        if len(report["attempts"]) >= max_items:
            report["status"] = "LIMIT_REACHED"
            break
        if clock() - started > budget_sec:
            report["status"] = "BUDGET_EXHAUSTED"
            break
        writer = busy()
        if writer:
            report["status"] = "WAIT_VAULT_WRITER_BUSY"
            report["writer"] = writer
            break
        cold_days = 0 if item.get("seed") else cfg["cold_days"]
        cmd = [str(WS), "page", "archive", item["path"], "--cold-days",
               str(cold_days), "--timeout", str(cfg["archive_timeout_sec"])]
        if cfg["archive_mode"] == "copy" and not shadow:
            cmd.append("--execute")
        attempt = {"workspace_key": item["workspace_key"], "mode": mode,
                   "seed": bool(item.get("seed")), "started_at": clock()}
        try:
            proc = runner(cmd, cfg["archive_timeout_sec"] + 60)
        except subprocess.TimeoutExpired:
            attempt.update({"rc": None, "tail": "ARCHIVE_TIMEOUT", "outcome": "timeout",
                            "elapsed_sec": round(clock() - attempt["started_at"], 3)})
            report["attempts"].append(attempt)
            report["skipped"] += 1
            report["status"] = "ARCHIVE_TIMEOUT"
            report["remaining_queue"] -= 1
            report["retry_queue"] += 1
            break
        tail = ((proc.stdout or "") + (proc.stderr or ""))[-1200:]
        attempt.update({"rc": proc.returncode, "tail": tail,
                        "elapsed_sec": round(clock() - attempt["started_at"], 3)})
        if proc.returncode == 0:
            attempt["outcome"] = "archived"
            report["archived"] += 1
        elif any(token in tail for token in TRANSIENT_STOP_REFUSALS):
            attempt["outcome"] = "wait"
            report["skipped"] += 1
            report["attempts"].append(attempt)
            report["status"] = next(t for t in TRANSIENT_STOP_REFUSALS if t in tail)
            break
        elif (any(token in tail for token in DETERMINISTIC_ARCHIVE_REFUSALS)
              and not retryable_archive_refusal(tail)):
            attempt["outcome"] = "blocked"
            report["blocked"] += 1
            lines = [line for line in tail.strip().splitlines() if "REFUSE_" in line]
            reason = (lines[-1] if lines else tail.strip())[:500]
            if hasattr(pg, "block_archive") and not shadow:
                pg.block_archive(item["workspace_key"], reason)
        elif proc.returncode == 2 and live_archive_deferral(tail):
            # A positive recency observation protects a working tree. It is a
            # normal deferral, not an I/O failure and never an archived result.
            # Match the whole response: mixed/unknown errors stay fail-closed.
            attempt["outcome"] = "live_deferred"
            report["skipped"] += 1
            report["live_deferred"] += 1
            if hasattr(pg, "block_archive") and not shadow:
                pg.block_archive(item["workspace_key"], tail.strip()[:500],
                                 retry_after_sec=3600)
        elif retryable_archive_refusal(tail):
            attempt["outcome"] = "retry_later"
            report["skipped"] += 1
            report["retry_queue"] += 1
            reason = next((line for line in reversed(tail.strip().splitlines())
                           if "REFUSE_" in line), tail.strip())[:500]
            if hasattr(pg, "block_archive") and not shadow:
                pg.block_archive(item["workspace_key"], reason, retry_after_sec=3600)
        else:
            attempt["outcome"] = "skipped"
            report["skipped"] += 1
            report["retry_queue"] += 1
            if hasattr(pg, "block_archive") and not shadow:
                pg.block_archive(item["workspace_key"], "ARCHIVE_FAILED " + tail[-450:],
                                 retry_after_sec=3600)
        report["remaining_queue"] -= 1
        report["attempts"].append(attempt)
    if report["status"] is None:
        report["status"] = ("RETRY_PENDING" if report["retry_queue"] else
                            "BLOCKED_PENDING" if report["blocked"] or report["blocked_candidates"] else
                            "LIVE_DEFERRED" if report["live_deferred"] else "DRAINED")
    return report


def last_archive_attempt(report):
    attempts = (report or {}).get("attempts") or []
    if not attempts:
        return None
    last = attempts[-1]
    return {"workspace_key": last["workspace_key"], "rc": last.get("rc"),
            "tail": last.get("tail"), "mode": last.get("mode"),
            "seed": bool(last.get("seed"))}


def archive_drain_summary(report):
    lines = ["ARCHIVE_DRAIN status=%s archived=%d blocked=%d skipped=%d queue=%s "
             "remaining=%s retry=%s blocked_before=%s budget_sec=%s live_deferred=%s blocked_candidates=%s" % (
                 report.get("status"), report.get("archived", 0), report.get("blocked", 0),
                 report.get("skipped", 0), report.get("queue"), report.get("remaining_queue"),
                 report.get("retry_queue", 0), report.get("blocked_before"),
                 report.get("budget_sec"), report.get("live_deferred", 0), report.get("blocked_candidates", 0))]
    for attempt in report.get("attempts") or []:
        lines.append("  %s rc=%s %.1fs %s" % (
            attempt.get("outcome"), attempt.get("rc"), attempt.get("elapsed_sec") or 0,
            attempt.get("workspace_key")))
    if report.get("writer"):
        lines.append("  writer=" + str(report["writer"]))
    return "\n".join(lines)


def archive_exit_code(report):
    if report.get("retry_queue") or report.get("blocked_candidates") or report.get("blocked") or report.get("status") in {
        "BAIDU_WATCHER_DEAD", "ARCHIVE_TIMEOUT", "RETRY_PENDING", "BLOCKED_PENDING",
    }:
        return 2
    return 0


def refresh_liveness(pg, receipt):
    """Incident note: plan() now refuses to cool/archive a tree whose files
    changed within cold_days and fails closed (LIVENESS_PROBE_REQUIRED) until the
    filesystem-recency probe has run.  The probe is cheap (find -newermt -quit) but
    nothing else calls it, so every archive/pressure caller refreshes it here."""
    refresh = getattr(pg, "refresh_tree_liveness", None)
    if refresh is None:
        return None
    try:
        receipt["liveness"] = refresh()
    except Exception as exc:  # fail closed downstream: plan() keeps PROBE_REQUIRED
        receipt["liveness"] = {"error": str(exc)[:500]}
    return receipt["liveness"]


def ensure_baidu_watcher(cfg, receipt, runner=call):
    """Fail-closed gate before staging anything into the Baidu backup folder.

    <time> the client's folder watcher died after a 3-file burst and
    every later upload waited on ``backup_file`` forever.  baidu_watcher.py stages a
    1KB probe and, when nothing else is writing, hard-restarts the client (it
    ignores quit/SIGTERM).  Returns True only on WATCHER_ALIVE.
    """
    timeout = int(cfg.get("watcher_probe_timeout_sec", 180))
    try:
        proc = runner([sys.executable, str(WATCHER_TOOL), "ensure", "--json",
                       "--timeout", str(timeout)], timeout + 300)
    except subprocess.TimeoutExpired:
        receipt["baidu_watcher"] = {"verdict": "WATCHER_PROBE_TIMEOUT"}
        return False
    try:
        report = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        report = {"verdict": "WATCHER_PROBE_UNPARSEABLE",
                  "tail": ((proc.stdout or "") + (proc.stderr or ""))[-800:]}
    report["rc"] = proc.returncode
    receipt["baidu_watcher"] = report
    return report.get("verdict") == "WATCHER_ALIVE"


def archive_stage(cfg, pg, plan, receipt, *, shadow, budget_key, budget_default,
                  runner=call, busy=vault_writer_busy, watcher=ensure_baidu_watcher):
    """Lock -> watcher gate -> serial drain.  Shared by the full pass and --archive-only."""
    max_items = int(cfg.get("max_archives_per_run") or 0)
    seeds = seed_items(cfg, pg)
    blocked = pg.archive_blocks(float(cfg.get("archive_block_days", 7))) if hasattr(pg, "archive_blocks") else {}
    pending = len(archive_queue(pg, plan, seeds, blocked))
    with archive_lock() as held:
        if not held:
            receipt["archive_drain"] = {"status": "WAIT_ARCHIVE_LOCK", "attempts": [],
                                        "archived": 0, "blocked": 0, "skipped": 0}
        elif pending and max_items and not shadow and busy():
            receipt["archive_drain"] = {"status": "WAIT_VAULT_WRITER_BUSY", "attempts": [],
                                        "queue": pending, "remaining_queue": pending,
                                        "archived": 0, "blocked": 0, "skipped": 0}
        elif pending and max_items and not shadow and not watcher(cfg, receipt, runner):
            receipt["archive_drain"] = {"status": "BAIDU_WATCHER_DEAD", "attempts": [],
                                        "archived": 0, "blocked": 0, "skipped": 0}
        else:
            receipt["archive_drain"] = archive_drain(
                cfg, pg, plan, seeds, shadow=shadow,
                budget_sec=archive_budget(cfg, budget_key, budget_default),
                max_items=max_items, runner=runner, busy=busy,
            )
    receipt["archive"] = last_archive_attempt(receipt["archive_drain"])
    if "queue" in receipt["archive_drain"]:
        try:
            receipt["pager_priority"] = publish_pager_priority(pg, receipt["archive_drain"])
        except Exception as exc:  # flag stays as it was; the drain result above is already real
            receipt["pager_priority"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    return receipt["archive_drain"]


def _no_candidate_outcome(pg, report):
    """No EVICT_CANDIDATE under pressure: distinguish institutional waiting from a stuck pool.

    A page proven cloud+snapshot that is still inside the hot grace window (or
    leased) is not a failure of the pager; it will become a candidate on its own.  Only
    a pool with nothing provable left to evict is a real REFUSE.
    """
    waiting = pg.pressure_waiting() if hasattr(pg, "pressure_waiting") else []
    if not waiting:
        pool = pg.pool_status()["managed"]
        if pool.get('capacity_pending'):
            report.update(status='CAPACITY_BLOCKED_NO_ELIGIBLE_PAGE',
                          capacity_gap_bytes=pool['capacity_gap_bytes'],
                          target_free_bytes=pool['target_free_bytes'],
                          final_free_ratio=pool['free_ratio'])
            # A blocked admission is explicit, never labelled DRAINED/idle success.
            return report
        if float(pool["free_ratio"]) >= float(pool.get("trigger_free_ratio", 0.10)):
            # <date>: inside the hysteresis window (>= trigger, < stop) with nothing
            # provable left is a *drained* pool, mirrored by PAGER_PRESSURE_DRAINED in
            # pager.alerts(). Raising here made the 10-minute heartbeat fail forever
            # after a successful eviction that landed at 13.7% (stop is 15%).
            report["status"] = "DRAINED"
            report["final_free_ratio"] = pool["free_ratio"]
            return report
        raise RuntimeError("REFUSE_PRESSURE_WITHOUT_ELIGIBLE_WARM_PAGE")
    report["status"] = "WAITING_HOT_GRACE"
    report["waiting"] = [
        {key: item.get(key) for key in ("asset_id", "size_bytes", "reason", "eligible_at")}
        for item in waiting[:8]
    ]
    report["earliest_eligible_at"] = waiting[0]["eligible_at"]
    report["final_free_ratio"] = pg.pool_status()["managed"]["free_ratio"]
    return report


def pressure_order(candidates):
    """Order pressure-eviction candidates: largest page first, then coldest.

    Incident note: ``eviction_candidates()`` is coldest-first, which is the right
    order for a calm-state schedule but the wrong one under pressure. Every executor
    run carries a fixed ~2-3 min overhead (catalog projection, ``ws index --rebuild``
    across both hosts, iCloud state sync) regardless of page size, so a 900s tick that
    starts at the cold end evicts five 20-180MB 解析视频 pages and moves the pool by
    0.02% (measured over one window: 12.741%->12.762%, 380 candidates / 136GB waiting,
    31GB to the stop line => ~200h at that rate). Under pressure the goal is to reach
    the stop watermark with the fewest executor runs, so bytes decide and coldness only
    breaks ties. Stable sort: pages without a size keep the caller's coldest-first order.
    """
    return sorted(candidates, key=lambda c: (
        -int(c.get("size_bytes") or 0),
        c.get("last_access") or 0,
        c.get("access_count") or 0,
        str(c.get("workspace_key") or c.get("asset_id") or ""),
    ))


def reconcile_eviction_blocks(pg, *, admit=None):
    """Recheck stale admission decisions; never waive an executor safety check.

    Historical missing-initial-restore and no-longer-candidate refusals are not
    permanent asset facts. Only re-admit an exact asset accepted by the current
    executor. Hash agent-f retries only after a newer confirmed snapshot.
    Live handles, private paths and other refusals stay.
    Re-admission is not deletion: the executor runs every current gate again.
    """
    if not hasattr(pg, 'eviction_blocks') or not hasattr(pg, 'unblock_eviction'):
        return {'checked': 0, 'released': []}
    retryable = {'REFUSE_INITIAL_RESTORE_PROOF_MISSING',
                 'NO_ELIGIBLE_CONFIRMED_hostb_ASSET',
                 'REFUSE_ASSET_NOT_CURRENT_EVICTION_CANDIDATE'}
    blocks = pg.eviction_blocks()
    pending = [asset for asset, row in blocks.items()
               if str(row.get('reason') or '').split(' ', 1)[0] in retryable]
    if hasattr(pg, 'status'):
        for asset, block in blocks.items():
            if not str(block.get('reason') or '').startswith(
                    'REFUSE_LOCAL_CHANGED_REARCHIVE_REQUIRED '):
                continue
            try:
                rows = pg.status(asset)['rows']
                if (len(rows) == 1 and rows[0].get('cloud_asset_id') == asset
                        and rows[0].get('cloud_verified') and rows[0].get('snapshot_verified')
                        and not rows[0].get('dirty')
                        and float(rows[0].get('archive_epoch') or 0) > float(block['at'])):
                    pending.append(asset)
            except (KeyError, TypeError, ValueError, OSError):
                continue
    if not pending:
        return {'checked': 0, 'released': []}
    if admit is None:
        # Use the same authority as the executor, rather than another allowlist.
        if str(pager.CLOUD_WORKSPACE) not in sys.path:
            sys.path.insert(0, str(pager.CLOUD_WORKSPACE))
        from cloud_asset_evict_once import choose_asset
        admit = choose_asset
    released = []
    for asset in pending:
        try:
            accepted = admit(asset)
        except (Exception, SystemExit):
            continue
        if not isinstance(accepted, dict) or accepted.get('asset_id') != asset:
            continue
        # Compare and clear atomically: a newly written refusal must survive.
        if pg.unblock_eviction(asset, expected=blocks[asset]):
            released.append(asset)
    return {'checked': len(pending), 'released': released}


def pressure_eviction_cycle(cfg, *, shadow=False, pg=None, runner=call, clock=time.monotonic):
    """Recover watermarks or a live capacity demand using the same safe candidates."""
    state = str(cfg.get("pool_migration_state") or "UNKNOWN")
    enabled = bool(cfg.get("evict_enabled"))
    report = {
        "enabled": enabled, "migration_state": state, "shadow": bool(shadow),
        "status": None, "candidate_count": 0, "attempts": [], "evicted": 0,
    }
    if state != "COMPLETE":
        if enabled:
            raise RuntimeError("REFUSE_EVICTION_BEFORE_POOL_MIGRATION_COMPLETE")
        report["status"] = "MIGRATION_DRAINING"
        return report
    if not enabled:
        report["status"] = "DISABLED"
        return report
    pg = pager.WorkspacePager() if pg is None else pg
    initial = pg.pool_status()
    report["initial_free_ratio"] = initial["managed"]["free_ratio"]
    report["trigger_free_ratio"] = initial["managed"]["trigger_free_ratio"]
    report["stop_free_ratio"] = initial["managed"]["stop_free_ratio"]
    report['capacity_requests'] = initial['managed'].get('capacity_requests', [])
    report['target_free_bytes'] = initial['managed'].get('target_free_bytes')
    report['initial_free_bytes'] = initial['managed'].get('free')
    if not initial["managed"]["eviction_active"]:
        report["status"] = "ABOVE_TRIGGER"
        report["final_free_ratio"] = initial["managed"]["free_ratio"]
        return report
    if not shadow:
        report["block_reconciliation"] = reconcile_eviction_blocks(pg)
    candidates = pressure_order(pg.eviction_candidates())
    report["candidate_count"] = len(candidates)
    if not candidates:
        return _no_candidate_outcome(pg, report)
    if shadow:
        report["status"] = "WOULD_EVICT"
        report["next_asset_id"] = candidates[0]["asset_id"]
        report["final_free_ratio"] = initial["managed"]["free_ratio"]
        return report

    timeout = int(cfg.get("archive_timeout_sec") or 172800)
    budget = max(1, int(cfg.get("pressure_tick_budget_sec", 900)))
    deadline = clock() + budget
    report["budget_sec"] = budget
    report["refused"] = []
    evicted = 0
    skipped: set = set()
    for _ in range(int(cfg["max_evictions_per_run"])):
        before = pg.pool_status()
        report['remaining_gap_bytes'] = before['managed'].get('bytes_to_stop')
        if report['initial_free_bytes'] is not None and 'free' in before['managed']:
            report['net_free_change_bytes'] = before['managed']['free'] - report['initial_free_bytes']
        if not before["managed"]["eviction_active"]:
            break
        if report["attempts"] and clock() >= deadline:
            report.update(status="BUDGET_EXHAUSTED", evicted=evicted,
                          final_free_ratio=before["managed"]["free_ratio"])
            return report
        candidates = pressure_order(
            [c for c in pg.eviction_candidates() if c["asset_id"] not in skipped])
        if not candidates:
            report["evicted"] = evicted
            if evicted:
                # Progress was made this run; the next cycle re-evaluates the pool and
                # reports WAITING/STUCK truthfully. Raising here would discard the receipt.
                break
            if report["refused"]:
                # Nothing evicted and every candidate was refused by its executor: still
                # fail-closed, but name the refusals instead of the generic "no page".
                try:
                    return _no_candidate_outcome(pg, report)
                except RuntimeError:
                    report["status"] = "EXECUTOR_REFUSED"
                    raise RuntimeError(
                        "PRESSURE_EVICTION_REFUSED all candidates refused by executor: %s" %
                        "; ".join("%s=%s" % (r["asset_id"], r["reason"][:120])
                                  for r in report["refused"])
                    )
            return _no_candidate_outcome(pg, report)
        item = candidates[0]
        tool = evict_tool_for(item["asset_id"])
        proc = runner(
            [str(tool), "--execute-delete", "--asset", item["asset_id"]],
            timeout,
        )
        attempt = {
            "asset_id": item["asset_id"], "size_bytes": int(item.get("size_bytes") or 0),
            "tool": tool.name, "rc": proc.returncode,
            "tail": ((proc.stdout or "") + (proc.stderr or ""))[-2000:],
        }
        report["attempts"].append(attempt)
        if proc.returncode in (0, 3) and 'WAIT_ASSET_OPERATION_LOCK' in attempt['tail']:
            report.update(status='WAIT_ASSET_OPERATION_LOCK', evicted=evicted)
            return report
        if proc.returncode == 0:
            if not re.search(r'^EVICT_PASS\b.*\bsource_deleted=true\b', proc.stdout or '', re.M):
                raise RuntimeError('PRESSURE_EVICTION_PROOF_MISSING asset=' + item['asset_id'])
            evicted += 1
            # Never re-run the same asset within one cycle: the executor marks the page
            # COLD/local_present=0 itself, but a stale candidate read right after a
            # successful delete re-selected batch-0002 (<time>) and turned a
            # PASS into a bogus REFUSE_SOURCE_TREE_DIFFERS block.
            skipped.add(item["asset_id"])
            continue
        # <date>: an executor *refusal* (fail-closed allowlist / eligibility) is a
        # deterministic fact about that page, not a transient failure. Retrying it every
        # 10 minutes and aborting the whole cycle starved every candidate behind it
        # (a 114KB legacy asset refused -> batch-0002 ~80GB never reached, 18h at 8%
        # free). Persist the block on the pager, skip it, continue with the next page.
        # Anything that is not an explicit refusal (ssh down, timeout, crash) still aborts.
        tail = attempt["tail"]
        deterministic = ("REFUSE_" in tail) or ("NO_ELIGIBLE" in tail)
        if not deterministic:
            raise RuntimeError(
                "PRESSURE_EVICTION_FAILED asset=%s rc=%d detail=%s" %
                (item["asset_id"], proc.returncode, tail)
            )
        reason = next((ln for ln in reversed(tail.strip().splitlines())
                       if "REFUSE_" in ln or "NO_ELIGIBLE" in ln), tail[-200:])
        if hasattr(pg, "block_eviction"):
            pg.block_eviction(item["asset_id"], reason.strip())
        skipped.add(item["asset_id"])
        report["refused"].append({"asset_id": item["asset_id"], "reason": reason.strip()[:300]})

    final = pg.pool_status()
    report["evicted"] = evicted
    report["final_free_ratio"] = final["managed"]["free_ratio"]
    report['remaining_gap_bytes'] = final['managed'].get('bytes_to_stop')
    if report['initial_free_bytes'] is not None and 'free' in final['managed']:
        report['net_free_change_bytes'] = final['managed']['free'] - report['initial_free_bytes']
    if not final["managed"]["eviction_active"]:
        report["status"] = "RECOVERED"
    elif evicted:
        report["status"] = "LIMIT_REACHED"
    else:
        report["status"] = "EXECUTOR_REFUSED"
        raise RuntimeError(
            "PRESSURE_EVICTION_REFUSED all candidates refused by executor: %s" %
            "; ".join("%s=%s" % (r["asset_id"], r["reason"][:120]) for r in report["refused"])
        )
    return report


def validate_foundry_stage(stage: Path) -> dict[str, int]:
    missing = [name for name in FOUNDRY_ARTIFACTS
               if not (stage / name).is_file() or (stage / name).stat().st_size == 0]
    if missing:
        raise RuntimeError("FOUNDRY_ARTIFACT_MISSING " + ",".join(missing))
    repository_rows = [json.loads(line) for line in
                       (stage / "function_foundry_index.jsonl").read_text(encoding="utf-8").splitlines()
                       if line.strip()]
    storage = json.loads((stage / "function_foundry_storage.json").read_text(encoding="utf-8"))
    if storage.get("schema_version") != 1 or not isinstance(storage.get("storage"), list):
        raise RuntimeError("FOUNDRY_STORAGE_SCHEMA_INVALID")
    cards = [json.loads(line) for line in
             (stage / "capability_cards.jsonl").read_text(encoding="utf-8").splitlines()
             if line.strip()]
    card_ids = [str(card["card_id"]) for card in cards]
    if not card_ids or len(card_ids) != len(set(card_ids)):
        raise RuntimeError("FOUNDRY_CAPABILITY_CARD_IDS_INVALID")
    meta = json.loads((stage / "capability_index_meta.json").read_text(encoding="utf-8"))
    with sqlite3.connect("file:%s?mode=ro" % (stage / "capability_index.sqlite3"),
                         uri=True) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        db_ids = [str(row[0]) for row in
                  conn.execute("SELECT card_id FROM capabilities ORDER BY card_id")]
        utterance_count = int(conn.execute(
            "SELECT count(*) FROM semantic_router_utterances"
        ).fetchone()[0])
    if (integrity != "ok" or sorted(card_ids) != db_ids
            or len(card_ids) != int(meta["card_count"])):
        raise RuntimeError(
            "FOUNDRY_CAPABILITY_CARDINALITY integrity=%s db=%d jsonl=%d meta=%s"
            % (integrity, len(db_ids), len(card_ids), meta.get("card_count"))
        )
    if (meta.get("cpu_only_enforced") is not True
            or meta.get("embedding_device") != "cpu"
            or int(meta.get("embedding_vram_mib") or 0) != 0):
        raise RuntimeError("FOUNDRY_CAPABILITY_NOT_CPU_ONLY")
    manifest = json.loads(
        (stage / "capability_router_manifest.json").read_text(encoding="utf-8")
    )
    index_sha256 = hashlib.sha256(
        (stage / "capability_index.sqlite3").read_bytes()
    ).hexdigest()
    if (manifest.get("engine") != CAPABILITY_ROUTER_ENGINE
            or manifest.get("package_version") != CAPABILITY_ROUTER_PACKAGE_VERSION
            or manifest.get("source_commit") != CAPABILITY_ROUTER_SOURCE_COMMIT
            or manifest.get("wheel_sha256") != CAPABILITY_ROUTER_WHEEL_SHA256
            or manifest.get("litellm_security_floor") !=
            CAPABILITY_ROUTER_LITELLM_FLOOR
            or manifest.get("litellm_locked_version") !=
            CAPABILITY_ROUTER_LITELLM_VERSION
            or manifest.get("offline_cost_map_enforced") is not True
            or float(manifest.get("score_threshold") or -1) !=
            CAPABILITY_ROUTER_SCORE_THRESHOLD
            or manifest.get("aggregation") != CAPABILITY_ROUTER_AGGREGATION
            or int(manifest.get("retrieval_contract_version") or 0) !=
            CAPABILITY_RETRIEVAL_CONTRACT_VERSION
            or manifest.get("cpu_only_enforced") is not True
            or manifest.get("cards_sha256") != meta.get("cards_sha256")
            or int(manifest.get("card_count") or 0) != len(card_ids)
            or manifest.get("utterances_sha256") !=
            meta.get("router_utterances_sha256")
            or int(manifest.get("utterance_count") or 0) != utterance_count
            or manifest.get("index_sha256") != index_sha256):
        raise RuntimeError("FOUNDRY_CAPABILITY_ROUTER_MANIFEST_MISMATCH")
    return {"artifacts": len(FOUNDRY_ARTIFACTS), "repository_rows": len(repository_rows),
            "capability_cards": len(card_ids), "router_utterances": utterance_count}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    ap.add_argument("--shadow", action="store_true",
                    help="override copy mode for a read-only smoke pass")
    ap.add_argument("--pressure-only", action="store_true",
                    help="only reconcile the page table and run the bounded watermark gate")
    ap.add_argument("--archive-only", action="store_true",
                    help="only reconcile the page table and run the bounded serial archive drain")
    args = ap.parse_args()
    cfg = policy(args.policy)
    started = time.time()
    receipt = {"started_at": started, "sync": None, "graph_rebuild": None,
               "archive": None, "foundry_sync": None, "eviction": None, "evicted": 0}

    if args.pressure_only:
        sync = call([str(WS), "page", "sync", "--json"], cfg["sync_timeout_sec"])
        if sync.returncode:
            raise RuntimeError(
                "PAGE_SYNC_FAILED " + (sync.stdout + sync.stderr)[-3000:]
            )
        receipt["sync"] = json.loads(sync.stdout)
        pg = pager.WorkspacePager()
        refresh_liveness(pg, receipt)
        receipt["eviction"] = pressure_eviction_cycle(cfg, shadow=args.shadow)
        receipt["evicted"] = receipt["eviction"]["evicted"]
        # pressure ticks only raise the flag; clearing needs the archive queue view
        try:
            receipt["pager_priority"] = publish_pager_priority(pg, None, allow_clear=False)
        except Exception as exc:
            receipt["pager_priority"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
        receipt["finished_at"] = time.time()
        receipt["duration_sec"] = round(receipt["finished_at"] - started, 3)
        append_receipt(receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 2 if receipt['eviction']['status'] == 'CAPACITY_BLOCKED_NO_ELIGIBLE_PAGE' else 0

    if args.archive_only:
        sync = call([str(WS), "page", "sync", "--json"], cfg["sync_timeout_sec"])
        if sync.returncode:
            raise RuntimeError(
                "PAGE_SYNC_FAILED " + (sync.stdout + sync.stderr)[-3000:]
            )
        receipt["sync"] = json.loads(sync.stdout)
        receipt["archive_only"] = True
        pg = pager.WorkspacePager()
        refresh_liveness(pg, receipt)
        plan = pg.plan(cfg["hot_days"], cfg["cold_days"])
        archive_stage(cfg, pg, plan, receipt, shadow=args.shadow,
                      budget_key="archive_tick_budget_sec", budget_default=1500)
        receipt["plan_counts"] = {}
        for row in plan:
            receipt["plan_counts"][row["action"]] = receipt["plan_counts"].get(row["action"], 0) + 1
        receipt["finished_at"] = time.time()
        receipt["duration_sec"] = round(receipt["finished_at"] - started, 3)
        append_receipt(receipt)
        print(archive_drain_summary(receipt["archive_drain"]))
        print("PLAN_COUNTS " + json.dumps(receipt["plan_counts"], ensure_ascii=False, sort_keys=True))
        return archive_exit_code(receipt["archive_drain"])

    remote_index = call(
        ["ssh", "-n", "user@host-b",
         "set -e\ncd /home/user/tools\n./bin/function_foundry_index.py"],
        cfg["foundry_sync_timeout_sec"])
    if remote_index.returncode == 0:
        local_state = Path.home() / ".coldstore/state"
        local_state.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".foundry-sync-", dir=local_state))
        try:
            copied = call(
                ["scp", "-q"] + [
                    "user@host-b:/home/user/tools/" + name
                    for name in FOUNDRY_ARTIFACTS
                ] + [str(stage) + "/"], cfg["foundry_sync_timeout_sec"])
            if copied.returncode:
                raise RuntimeError("FOUNDRY_COPY_FAILED " + copied.stderr[-2000:])
            validated = validate_foundry_stage(stage)
            for name in FOUNDRY_ARTIFACTS:
                os.replace(stage / name, local_state / name)
            receipt["foundry_sync"] = {
                "export_rc": 0, "copy_rc": 0, **validated,
                "tail": remote_index.stdout[-2000:],
            }
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    else:
        receipt["foundry_sync"] = {"export_rc": remote_index.returncode,
                                   "tail": (remote_index.stdout + remote_index.stderr)[-2000:]}
        raise RuntimeError("FOUNDRY_EXPORT_FAILED " + receipt["foundry_sync"]["tail"])

    graph = call([str(WS), "index", "--rebuild"], cfg["sync_timeout_sec"])
    receipt["graph_rebuild"] = {
        "rc": graph.returncode, "tail": (graph.stdout + graph.stderr)[-3000:]
    }
    if graph.returncode:
        raise RuntimeError("GRAPH_REBUILD_FAILED " + receipt["graph_rebuild"]["tail"])

    sync = call([str(WS), "page", "sync", "--json"], cfg["sync_timeout_sec"])
    if sync.returncode:
        raise RuntimeError("PAGE_SYNC_FAILED " + (sync.stdout + sync.stderr)[-3000:])
    receipt["sync"] = json.loads(sync.stdout)

    pg = pager.WorkspacePager()
    # Archiving must run *before* the pressure-eviction gate, not after it.
    # pressure_eviction_cycle() intentionally raises when the pool is under
    # the low-water mark but no page has finished archive/redundancy
    # verification yet (fail-closed by design — see
    # test_pressure_without_candidate_fails_closed). That is correct
    # signalling for the 10-minute --pressure-only heartbeat. But calling it
    # *before* the one-archive-per-run step below meant that once the pool
    # dropped under the trigger, every full-pass run aborted on this raise
    # before archiving ever got a turn — and archiving is the only thing that
    # can ever create a WARM candidate. Real state on <date>:
    # free_ratio=0.0968 (<0.10 trigger) with 749 ARCHIVE_CANDIDATE rows queued
    # and zero archives attempted for days. That's a self-inflicted deadlock,
    # not a genuine "nothing left to do" state. Archiving first breaks the
    # deadlock; the pressure gate still runs right after and still
    # raises/fails loudly if it truly can't recover this round.
    refresh_liveness(pg, receipt)
    plan = pg.plan(cfg["hot_days"], cfg["cold_days"])
    archive_stage(cfg, pg, plan, receipt, shadow=args.shadow,
                  budget_key="archive_budget_sec", budget_default=5400)


    try:
        receipt["eviction"] = pressure_eviction_cycle(
            cfg, shadow=args.shadow, pg=pg
        )
        receipt["evicted"] = receipt["eviction"]["evicted"]
    except Exception:
        # Persist the archive attempts' receipts even when the
        # pressure gate still fails afterward. Losing that receipt was the
        # second half of the same bug: real progress happened above but was
        # never written to STATE_LOG because the process used to abort
        # before append_receipt() at the bottom of this function ever ran.
        receipt["finished_at"] = time.time()
        receipt["duration_sec"] = round(receipt["finished_at"] - started, 3)
        receipt["plan_counts"] = {}
        for row in plan:
            action = row["action"]
            receipt["plan_counts"][action] = receipt["plan_counts"].get(action, 0) + 1
        append_receipt(receipt)
        raise

    receipt["finished_at"] = time.time()
    receipt["duration_sec"] = round(receipt["finished_at"] - started, 3)
    receipt["plan_counts"] = {}
    for item in plan:
        action = item["action"]
        receipt["plan_counts"][action] = receipt["plan_counts"].get(action, 0) + 1
    append_receipt(receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return archive_exit_code(receipt["archive_drain"])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"WORKSPACE_PAGER_MAINTENANCE_FAIL {exc}", file=sys.stderr)
        raise SystemExit(2)
