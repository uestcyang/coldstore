#!/usr/bin/env python3
"""Pager-owned eviction executor for Logical Vault v3 function batches.

This is the v3 twin of ``cloud_asset_evict_once.py``.  The fixed-1GB v2 tool
takes every proof from the v2 ledger/catalog; this tool takes every proof from
the v3 control plane (``logical_vault_v3.sqlite3``) and never fabricates v2
evidence rows.  It is only ever invoked by ``workspace_pager_maintenance.py``
under real pressure, or by hand with an explicit ``--asset``.

Every gate is fail-closed.  Deletion happens only after ALL of:
  * pager: pool migration COMPLETE, evict_enabled, managed pool under the
    trigger watermark, asset is a *current* EVICT_CANDIDATE
  * pager: exactly one MANAGED page for the asset, host hostb, path equal to
    the batch source root, local_present=1
  * v3: batch AUDIT_PASS; every object CLOUD_CONFIRMED; object bytes equal
    expected_plain_bytes; every unit CLOUD_CONFIRMED/RESTORE_VERIFIED; no unit
    pinned or leased; every object source HASH_VERIFIED, on hostb, under root
    (operator policy "trust-the-cloud": a native
    download-back proof is no longer required -- cloud confirmation of every
    object plus the fresh local re-hash below is the whole contract)
  * v3: a fresh ``verify-batch --require-cloud`` returns STRICT_AUDIT_PASS
  * hostb: a fresh full re-hash of every regular file under the root equals the
    v3 object digests and sizes; no missing, no extra, no mismatch, no symlink
  * hostb: no open handles under the root; root resolves to itself
Then, in this order: ``rm -rf`` the root; assert it is gone; v3 sources ->
MISSING, units.local_present=0, SOURCE_EVICTED event (+ atomic event export);
pager ``mark_evicted``; catalog + ws index + ws page sync; post-conditions
(single COLD page with local_present=0; catalog row cloud_only).

``--dry-run`` runs every gate including the remote re-hash and stops before
``rm -rf``; nothing is mutated.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

WS = Path(__file__).resolve().parent
def _coldstore_bin() -> Path:
    env = os.environ.get("COLDSTORE_BIN")
    if env:
        return Path(env).expanduser()
    user = Path.home() / ".coldstore/bin"
    if (user / "ws").exists():
        return user
    return Path(__file__).resolve().parent.parent / "pager"  # in-repo sibling layout


COLDSTORE_BIN = _coldstore_bin()
for entry in (str(COLDSTORE_BIN), str(WS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)
import workspace_pager as pager  # noqa: E402
import logical_vault_v3 as lv3  # noqa: E402
from cloud_asset_evict_once import source_is_allowed  # noqa: E402
from cloud_asset_evict_once import require_empty_handle_probe
from cloud_asset_evict_once import handle_probe_command
from cloud_asset_evict_once import process_probe_command, require_empty_process_probe

REMOTE = lv3.REMOTE_hostb
ASSET_RE = re.compile(r"^hostb-asset-pool-v3-(batch-[0-9]{4})$")
SOURCE_ROOT_PREFIX = "/home/user/asset-pool-v3/"
REMOTE_TMP_DIR = "/tmp/logical-vault-v3-evict"
HASH_WORKERS = 8

# Runs on hostb.  argv: <root> <expected.json>.  expected.json = [[relpath, sha256, bytes], ...]
REMOTE_REHASH = r'''
import hashlib, json, os, sys, time
from concurrent.futures import ThreadPoolExecutor
root, expf = sys.argv[1], sys.argv[2]
exp = {r[0]: (r[1], int(r[2])) for r in json.load(open(expf))}
t0 = time.time()
files, symlinks = [], 0
for d, dirs, fs in os.walk(root):
    for name in dirs:
        if os.path.islink(os.path.join(d, name)):
            symlinks += 1
    for name in fs:
        p = os.path.join(d, name)
        if os.path.islink(p):
            symlinks += 1
            continue
        files.append(os.path.relpath(p, root))
def one(rel):
    p = os.path.join(root, rel); h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return rel, h.hexdigest(), os.path.getsize(p)
got = {}
with ThreadPoolExecutor(%d) as ex:
    for rel, dig, size in ex.map(one, files):
        got[rel] = (dig, size)
missing = sorted(r for r in exp if r not in got)
extra = sorted(r for r in got if r not in exp)
mismatch = sorted(r for r in exp if r in got and got[r] != exp[r])
print(json.dumps({
    "root": root, "files": len(got), "bytes": sum(s for _, s in got.values()),
    "expected_files": len(exp), "expected_bytes": sum(s for _, s in exp.values()),
    "n_missing": len(missing), "n_extra": len(extra), "n_mismatch": len(mismatch),
    "missing": missing[:20], "extra": extra[:20], "mismatch": mismatch[:20],
    "symlinks": symlinks, "elapsed_s": round(time.time() - t0, 1),
}, sort_keys=True))
''' % HASH_WORKERS


def refuse(message: str) -> None:
    raise SystemExit(message)


def run(args, *, capture=False, check=True, timeout=None):
    return subprocess.run(
        args, text=True, stdin=subprocess.DEVNULL, check=check, timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def ssh(argv: list[str], *, capture=True, check=True, timeout=None):
    return run(["ssh", "-n", REMOTE, *argv], capture=capture, check=check, timeout=timeout)


def parse_asset(asset_id: str) -> tuple[str, str]:
    match = ASSET_RE.match(str(asset_id or ""))
    if not match:
        refuse(f"REFUSE_NOT_A_V3_FUNCTION_BATCH_ASSET asset={asset_id}")
    batch_id = match.group(1)
    root = f"{SOURCE_ROOT_PREFIX}{batch_id}"
    if str(PurePosixPath(root)) != root or not source_is_allowed(root, asset_id):
        refuse(f"REFUSE_SOURCE_PATH_TOO_BROAD source={root}")
    return batch_id, root


def pager_gates(pg: pager.WorkspacePager, asset_id: str, root: str, *, dry_run: bool) -> dict:
    migration_state = str(pg.policy.get("pool_migration_state") or "UNKNOWN")
    if migration_state != "COMPLETE":
        refuse(f"REFUSE_EVICTION_BEFORE_POOL_MIGRATION_COMPLETE state={migration_state}")
    if not pg.policy.get("evict_enabled"):
        refuse("REFUSE_EVICTION_DISABLED_BY_POLICY")
    pools = pg.pool_status()
    if not pools["managed"]["eviction_active"] and not dry_run:
        refuse("REFUSE_NO_PRESSURE managed_free_ratio=%.6f" % pools["managed"]["free_ratio"])
    candidates = pg.eviction_candidates()
    is_candidate = asset_id in [row["asset_id"] for row in candidates]
    plan_action = next((row["action"] for row in pg.plan() if row.get("asset_id") == asset_id), None)
    if not is_candidate and not dry_run:
        refuse(f"REFUSE_ASSET_NOT_CURRENT_EVICTION_CANDIDATE asset={asset_id} "
               f"plan_action={plan_action} candidates={len(candidates)}")
    with pg.connect() as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM pages WHERE cloud_asset_id=?", (asset_id,)
        ).fetchall()]
    if len(rows) != 1:
        refuse(f"REFUSE_PAGE_ROW_COUNT asset={asset_id} count={len(rows)}")
    page = rows[0]
    # dry-run may precede WARM cooling, but never proceeds without the pager proofs
    if not (int(page["cloud_verified"]) and int(page["snapshot_verified"]) and not int(page["dirty"])):
        refuse("REFUSE_PAGE_PROOFS_INCOMPLETE cloud=%s snapshot=%s dirty=%s" % (
            page["cloud_verified"], page["snapshot_verified"], page["dirty"]))
    if (page["host"] != "hostb" or page["path"] != root or page["storage_pool"] != "MANAGED"
            or int(page["local_present"]) != 1 or int(page["pinned"]) != 0):
        refuse("REFUSE_PAGE_ROW_MISMATCH host=%s path=%s pool=%s local_present=%s pinned=%s" % (
            page["host"], page["path"], page["storage_pool"], page["local_present"], page["pinned"]))
    return {"pool": pools["managed"], "page": page, "is_candidate": is_candidate,
            "plan_action": plan_action}


def v3_gates(batch_id: str, root: str) -> dict:
    conn = sqlite3.connect(f"file:{lv3.DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        batch = conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if not batch:
            refuse(f"REFUSE_V3_BATCH_UNKNOWN batch={batch_id}")
        if batch["batch_state"] != "AUDIT_PASS":
            refuse(f"REFUSE_V3_BATCH_NOT_AUDIT_PASS state={batch['batch_state']}")
        units = conn.execute(
            "SELECT unit_id,unit_state,pinned,lease_until,kind FROM units WHERE batch_id=?",
            (batch_id,),
        ).fetchall()
        if len(units) != int(batch["expected_units"]):
            refuse(f"REFUSE_V3_UNIT_COUNT expected={batch['expected_units']} got={len(units)}")
        bad_units = [u["unit_id"] for u in units
                     if u["unit_state"] not in ("CLOUD_CONFIRMED", "RESTORE_VERIFIED")
                     or u["kind"] != "tool_capsule"]
        if bad_units:
            refuse(f"REFUSE_V3_UNIT_STATE n={len(bad_units)} first={bad_units[0]}")
        restored = sum(1 for u in units if u["unit_state"] == "RESTORE_VERIFIED")
        now_epoch = time.time()
        held = [u["unit_id"] for u in units
                if int(u["pinned"]) or (u["lease_until"] and float(u["lease_until"]) > now_epoch)]
        if held:
            refuse(f"REFUSE_V3_UNIT_PINNED_OR_LEASED n={len(held)} first={held[0]}")
        objects = conn.execute(
            "SELECT DISTINCT o.digest,o.cloud_state,o.plain_bytes FROM objects o "
            "JOIN unit_entries e USING(digest) JOIN units u USING(unit_id) WHERE u.batch_id=?",
            (batch_id,),
        ).fetchall()
        not_cloud = [o["digest"] for o in objects if o["cloud_state"] != "CLOUD_CONFIRMED"]
        if not objects or not_cloud:
            refuse(f"REFUSE_V3_OBJECT_NOT_CLOUD_CONFIRMED n={len(not_cloud)}")
        obj_bytes = sum(int(o["plain_bytes"]) for o in objects)
        if obj_bytes != int(batch["expected_plain_bytes"]):
            refuse(f"REFUSE_V3_BYTES expected={batch['expected_plain_bytes']} got={obj_bytes}")
        digests = {o["digest"]: int(o["plain_bytes"]) for o in objects}
        sources = conn.execute(
            "SELECT s.digest,s.host,s.source_path,s.source_state FROM object_sources s "
            "WHERE s.digest IN (SELECT DISTINCT e.digest FROM unit_entries e "
            "JOIN units u USING(unit_id) WHERE u.batch_id=?)", (batch_id,),
        ).fetchall()
        expected = []
        seen = set()
        prefix = root + "/"
        for s in sources:
            if s["host"] != REMOTE or not s["source_path"].startswith(prefix):
                refuse(f"REFUSE_V3_SOURCE_OUTSIDE_ROOT host={s['host']} path={s['source_path']}")
            if s["source_state"] != "HASH_VERIFIED":
                refuse(f"REFUSE_V3_SOURCE_NOT_HASH_VERIFIED state={s['source_state']} "
                       f"path={s['source_path']}")
            rel = s["source_path"][len(prefix):]
            if not rel or rel in seen or ".." in PurePosixPath(rel).parts:
                refuse(f"REFUSE_V3_SOURCE_RELPATH path={s['source_path']}")
            seen.add(rel)
            expected.append([rel, s["digest"], digests[s["digest"]]])
        if set(s["digest"] for s in sources) != set(digests):
            refuse("REFUSE_V3_SOURCE_DIGEST_COVERAGE")
        return {
            "batch": dict(batch), "units": len(units), "restored_units": restored,
            "objects": len(objects), "bytes": obj_bytes, "expected": expected,
        }
    finally:
        conn.close()


def fresh_strict_audit(batch_id: str) -> dict:
    proc = run([str(WS / "logical_vault_v3.py"), "verify-batch", "--batch", batch_id,
                "--require-cloud"], capture=True, check=False, timeout=3600)
    verdict = None
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                verdict = json.loads(line)
            except json.JSONDecodeError:
                continue
    if proc.returncode != 0 or not verdict or verdict.get("verdict") != "STRICT_AUDIT_PASS":
        refuse("REFUSE_V3_FRESH_AUDIT rc=%d tail=%s" % (
            proc.returncode, ((proc.stdout or "") + (proc.stderr or ""))[-800:]))
    return verdict


def remote_rehash(root: str, batch_id: str, expected: list[list]) -> dict:
    ssh(["mkdir", "-p", REMOTE_TMP_DIR])
    remote_expected = f"{REMOTE_TMP_DIR}/{batch_id}.expected.json"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(expected, handle, separators=(",", ":"))
        local_expected = handle.name
    try:
        run(["scp", "-q", local_expected, f"{REMOTE}:{remote_expected}"])
    finally:
        Path(local_expected).unlink(missing_ok=True)
    proc = ssh(["python3", "-c", shlex.quote(REMOTE_REHASH), shlex.quote(root),
                shlex.quote(remote_expected)], check=False, timeout=7200)
    ssh(["rm", "-f", remote_expected], check=False)
    if proc.returncode != 0:
        refuse(f"REFUSE_REMOTE_REHASH_FAILED rc={proc.returncode} stderr={proc.stderr[-800:]}")
    try:
        report = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        refuse(f"REFUSE_REMOTE_REHASH_UNPARSEABLE stdout={proc.stdout[-800:]}")
    if (report["n_missing"] or report["n_extra"] or report["n_mismatch"] or report["symlinks"]
            or report["files"] != report["expected_files"]
            or report["bytes"] != report["expected_bytes"]):
        refuse("REFUSE_SOURCE_TREE_DIFFERS_FROM_V3 " + json.dumps(report, sort_keys=True))
    return report


def remote_handles_and_resolution(root: str) -> None:
    handles = ssh([handle_probe_command(root)], check=False)
    require_empty_handle_probe(handles)
    require_empty_process_probe(ssh([process_probe_command(root)], check=False))
    resolved = ssh(["readlink", "-f", shlex.quote(root)]).stdout.strip()
    if resolved != root:
        refuse(f"REFUSE_SOURCE_PATH_RESOLUTION source={root} resolved={resolved}")


def delete_remote(root: str) -> None:
    ssh(["sudo", "-n", "rm", "-rf", "--", shlex.quote(root)], capture=False)
    absent = ssh(["sudo -n test ! -e %s && sudo -n test ! -L %s" %
                  (shlex.quote(root), shlex.quote(root))], check=False)
    if absent.returncode != 0:
        refuse("REFUSE_SOURCE_ABSENCE_NOT_PROVEN_AFTER_DELETE")


def record_v3_eviction(asset_id: str, batch_id: str, root: str, detail: dict) -> None:
    conn = lv3.connect()
    try:
        stamp = lv3.now()
        with conn:
            cur = conn.execute(
                "UPDATE object_sources SET source_state='MISSING', last_verified_at=? "
                "WHERE host=? AND substr(source_path,1,?)=?",
                (stamp, REMOTE, len(root) + 1, root + "/"),
            )
            conn.execute(
                "UPDATE units SET local_present=0, updated_at=? WHERE batch_id=?",
                (stamp, batch_id),
            )
            lv3.record_event(conn, "SOURCE_EVICTED", asset_id, dict(
                detail, batch_id=batch_id, source_root=root, sources_marked_missing=cur.rowcount,
                deleted_by="logical_vault_v3_evict.py", pager_owned=True,
            ))
        lv3.export_events(conn)
    finally:
        conn.close()


def postconditions(pg: pager.WorkspacePager, asset_id: str, root: str) -> None:
    with pg.connect() as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM pages WHERE cloud_asset_id=?", (asset_id,)).fetchall()]
    if len(rows) != 1 or rows[0]["state"] != "COLD" or int(rows[0]["local_present"]) != 0:
        refuse(f"REFUSE_POST_DELETE_PAGER_NOT_SINGLE_COLD_PAGE rows={rows}")
    catalog = [json.loads(line) for line in
               (WS / "cloud_asset_catalog.jsonl").read_text(encoding="utf-8").splitlines()
               if line.strip()]
    row = [r for r in catalog if r.get("asset_id") == asset_id]
    if (len(row) != 1 or row[0].get("original_path") != root
            or row[0].get("local_state") != "cloud_only" or row[0].get("cloud_state") != "confirmed"):
        refuse(f"REFUSE_POST_DELETE_CATALOG_NOT_CLOUD_ONLY row={row}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--asset", required=True)
    action = ap.add_mutually_exclusive_group(required=True)
    action.add_argument("--execute-delete", action="store_true")
    action.add_argument("--dry-run", action="store_true",
                        help="run every gate including the remote re-hash; mutate nothing")
    args = ap.parse_args()

    batch_id, root = parse_asset(args.asset)
    pg = pager.WorkspacePager()
    pager_report = pager_gates(pg, args.asset, root, dry_run=args.dry_run)
    v3 = v3_gates(batch_id, root)
    audit = fresh_strict_audit(batch_id)
    rehash = remote_rehash(root, batch_id, v3["expected"])
    remote_handles_and_resolution(root)
    summary = {
        "asset": args.asset, "batch": batch_id, "bytes": v3["bytes"], "files": rehash["files"],
        "units": v3["units"], "restored_units": v3["restored_units"],
        "rehash_elapsed_s": rehash["elapsed_s"], "audit": audit.get("verdict"),
        "managed_free_ratio_before": round(pager_report["pool"]["free_ratio"], 6),
        "pager_candidate_now": pager_report["is_candidate"],
        "pager_plan_action": pager_report["plan_action"],
    }
    if args.dry_run:
        print("EVICT_DRY_RUN_PASS " + json.dumps(summary, sort_keys=True))
        return 0

    delete_remote(root)
    record_v3_eviction(args.asset, batch_id, root, dict(
        summary, rehash_report={k: rehash[k] for k in ("files", "bytes", "elapsed_s")}))
    pg.mark_evicted(args.asset, "watermark eviction; Logical Vault v3 proofs; no repeat download")
    run([str(WS / "cloud_asset_catalog.py")], capture=True)
    run([str(COLDSTORE_BIN / "ws"), "index", "--rebuild"], capture=True)
    run([str(COLDSTORE_BIN / "ws"), "page", "sync", "--json"], capture=True)
    postconditions(pg, args.asset, root)
    after = pg.pool_status()["managed"]["free_ratio"]
    print("EVICT_PASS asset=%s bytes=%d files=%d source_deleted=true repeat_download=false "
          "vault=v3 managed_free_ratio=%.6f" % (args.asset, v3["bytes"], rehash["files"], after))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
