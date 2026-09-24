#!/usr/bin/env python3
"""Build the searchable, non-secret catalog for the opaque Baidu vault."""
import base64
import csv
import fcntl
import hashlib
import json
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from vault_v2_versions import VersionRefused, VersionStore

WS = Path(__file__).resolve().parent
CATALOG = WS / "cloud_asset_catalog.jsonl"
MANIFEST = WS / "cloud_asset_manifest.tsv"
SEMANTICS = WS / "workspace_semantics.jsonl"
# Logical Vault v3 (natural-size objects) is a second, independent cloud authority.
# Its batches are projected into this catalog so Workspace Pager sees the same
# cloud/restore/snapshot proofs it already reads for fixed-1GB v2 assets.
LV3_DB = WS / "logical_vault_v3.sqlite3"
LV3_TOOL = WS / "logical_vault_v3.py"
LV3_HOST = "user@host-b"
LV3_SOURCE_ROOT = "/home/user/asset-pool-v3"
LV3_ASSET_PREFIX = "hostb-asset-pool-v3-"


def tsv(path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [r for r in csv.reader(f, delimiter="\t") if r and not r[0].startswith("#")]


def remote_exists(path):
    p = subprocess.run(
        ["ssh", "-n", "user@host-b", "sudo", "-n", "test", "-e", path],
        stdin=subprocess.DEVNULL,
    )
    return p.returncode == 0


# Incident note: the catalogue is rebuilt once per archived page, and it
# used to spend one ssh round-trip per hostb asset just to test path existence —
# ~8.5s of the 11s rebuild at 51 assets, and O(n) worse as the vault grows.
# One round-trip now answers every path.  Paths are base64 framed because asset
# roots contain spaces and CJK.  Any transport failure returns a partial map and
# the caller falls back to the per-path probe, so the result never degrades.
def remote_exists_batch(paths):
    unique = sorted({p for p in paths if p})
    if not unique:
        return {}
    encoded = "\n".join(base64.b64encode(p.encode()).decode() for p in unique)
    script = (
        'while IFS= read -r b64; do '
        '[ -n "$b64" ] || continue; '
        'p=$(printf %s "$b64" | base64 -d); '
        'if sudo -n test -e "$p"; then echo "1 $b64"; else echo "0 $b64"; fi; '
        'done'
    )
    try:
        proc = subprocess.run(
            ["ssh", "user@host-b", script],
            input=encoded, text=True, capture_output=True, timeout=300)
    except (subprocess.SubprocessError, OSError):
        return {}
    found = {}
    for line in proc.stdout.splitlines():
        flag, _, b64 = line.strip().partition(" ")
        if flag not in {"0", "1"} or not b64:
            continue
        try:
            found[base64.b64decode(b64).decode()] = flag == "1"
        except (ValueError, UnicodeDecodeError):
            continue
    return found


def jsonl(path):
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except OSError:
        return []


def archive_fingerprints():
    store = VersionStore(WS)
    if store.heads_path.exists():
        return {
            asset_id: head["version_id"]
            for asset_id, head in store.heads_doc()["heads"].items()
        }
    latest = {}
    for row in tsv(WS / "vault_v2_ledger.tsv"):
        if len(row) == 12:
            latest[(row[1], row[3])] = row
    grouped = {}
    for row in latest.values():
        if row[11] == "CLOUD_CONFIRMED":
            grouped.setdefault(row[2], []).append(row)
    out = {}
    for label, parts in grouped.items():
        parts.sort(key=lambda row: int(row[3]))
        payload = [[int(row[3]), int(row[4]), row[5]] for row in parts]
        out[label] = hashlib.sha256(json.dumps(
            payload, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
    return out


def logical_vault_v3_rows(existing_ids, semantic_by_asset, now, *, db_path=None,
                          exists_fn=None):
    """Project AUDIT_PASS-capable v3 function batches as catalog rows.

    Proof mapping (all read-only from logical_vault_v3.sqlite3):
      cloud_state=confirmed   <= batch_state AUDIT_PASS and every object CLOUD_CONFIRMED
                                 and object bytes == expected_plain_bytes
      restore_verified        <= >=1 unit RESTORE_VERIFIED (real Baidu native restore)
      snapshot_verified       <= confirmed and every source HASH_VERIFIED
                                 (or MISSING only after a recorded SOURCE_EVICTED)
    A cloud-confirmed v2 row for the same asset_id always wins; v3 only replaces
    v2 placeholders that never reached cloud_state=confirmed.
    """
    # Incident note: db_path used to default to the module-level LV3_DB,
    # which binds at import time.  Redirecting WS (as every catalogue test and
    # any relocated vault does) therefore still read the *real* v3 ledger and
    # emitted live batches into a temporary catalogue.  Resolving against the
    # current WS keeps production behaviour identical while making the vault
    # root actually authoritative.
    db_path = db_path or (WS / "logical_vault_v3.sqlite3")
    if not db_path.is_file():
        return []
    exists_fn = exists_fn or remote_exists
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = []
    try:
        for batch in conn.execute("SELECT * FROM batches ORDER BY batch_id"):
            batch_id = batch["batch_id"]
            asset_id = LV3_ASSET_PREFIX + batch_id
            if asset_id in existing_ids:
                continue
            root = f"{LV3_SOURCE_ROOT}/{batch_id}"
            objects = conn.execute(
                "SELECT cloud_state, COUNT(*) n, COALESCE(SUM(plain_bytes),0) b FROM ("
                "SELECT DISTINCT o.digest,o.cloud_state,o.plain_bytes FROM objects o "
                "JOIN unit_entries e USING(digest) JOIN units u USING(unit_id) "
                "WHERE u.batch_id=?) GROUP BY cloud_state", (batch_id,),
            ).fetchall()
            obj_states = {r["cloud_state"]: (int(r["n"]), int(r["b"])) for r in objects}
            obj_bytes = sum(b for _, b in obj_states.values())
            sources = conn.execute(
                "SELECT s.source_state, s.host, "
                "SUM(CASE WHEN substr(s.source_path,1,?)=? THEN 1 ELSE 0 END) under_root, "
                "COUNT(*) n FROM object_sources s WHERE s.digest IN ("
                "SELECT DISTINCT e.digest FROM unit_entries e JOIN units u USING(unit_id) "
                "WHERE u.batch_id=?) GROUP BY s.source_state, s.host",
                (len(root) + 1, root + "/", batch_id),
            ).fetchall()
            src_total = sum(int(r["n"]) for r in sources)
            src_ok = sum(int(r["n"]) for r in sources
                         if r["host"] == LV3_HOST and int(r["under_root"]) == int(r["n"])
                         and r["source_state"] in ("HASH_VERIFIED", "MISSING"))
            src_missing = sum(int(r["n"]) for r in sources if r["source_state"] == "MISSING")
            evicted = conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='SOURCE_EVICTED' AND subject_id=?",
                (asset_id,),
            ).fetchone()[0]
            restored = conn.execute(
                "SELECT COUNT(*) FROM units WHERE batch_id=? AND unit_state='RESTORE_VERIFIED'",
                (batch_id,),
            ).fetchone()[0]
            cloud = (
                batch["batch_state"] == "AUDIT_PASS"
                and set(obj_states) == {"CLOUD_CONFIRMED"}
                and obj_bytes == int(batch["expected_plain_bytes"])
            )
            snapshot_verified = bool(
                cloud and src_total > 0 and src_ok == src_total
                and (src_missing == 0 or evicted > 0)
            )
            exists = exists_fn(root)
            local_state = "replicated" if exists and cloud else "cloud_only" if cloud else "local"
            semantic = semantic_by_asset.get(asset_id) or {}
            semantic_keywords = semantic.get("keywords_json") or "[]"
            if isinstance(semantic_keywords, str):
                try:
                    semantic_keywords = json.loads(semantic_keywords)
                except json.JSONDecodeError:
                    semantic_keywords = []
            description = (semantic.get("summary")
                           or f"Function Foundry严格候选{batch_id}; Logical Vault v3 自然对象归档")
            keywords = sorted(set(filter(None, (
                asset_id, batch_id, description, "百度网盘", "密文仓", "冷资产",
                "Logical Vault v3", "asset-pool",
            ))) | {str(x) for x in semantic_keywords})
            fingerprint = batch["mapping_sha256"]
            rows.append({
                "asset_id": asset_id, "label": asset_id, "machine": "hostb",
                "original_path": root, "description": description,
                "keywords": keywords, "size": int(batch["expected_plain_bytes"]),
                "local_state": local_state,
                "cloud_state": "confirmed" if cloud else "pending",
                "catalog": str(CATALOG), "manifest": str(MANIFEST),
                "ledger": str(db_path),
                "restore": f"{LV3_TOOL} restore --batch {batch_id} --download --output-root <dir>",
                "indexed_at": now,
                "archived_at": batch["updated_at"] if cloud else None,
                "snapshot_verified": snapshot_verified,
                "snapshot_sha256": fingerprint if snapshot_verified else None,
                "consistency_verified": snapshot_verified,
                "consistency_fingerprint": fingerprint if snapshot_verified else None,
                "archive_content_fingerprint": fingerprint if cloud else None,
                "current_version_id": fingerprint if cloud else None,
                "previous_version_id": None,
                "content_fingerprint": semantic.get("content_fingerprint") or (fingerprint if cloud else None),
                "semantic_revision": int(semantic.get("semantic_revision") or 0),
                "annotation_status": semantic.get("annotation_status") or "CURRENT",
                "semantic_summary": semantic.get("summary") or description,
                "semantic_keywords": semantic_keywords,
                "annotated_by": semantic.get("annotated_by"),
                "annotated_at": semantic.get("annotated_at"),
                "index_synced_at": semantic.get("index_synced_at"),
                "vault": "v3",
                "restore_verified": restored >= 1,
                "v3_batch_state": batch["batch_state"],
                "v3_restore_verified_units": int(restored),
                "v3_objects": {k: {"count": n, "bytes": b} for k, (n, b) in obj_states.items()},
                "v3_sources_total": src_total,
                "v3_sources_missing": src_missing,
            })
    finally:
        conn.close()
    return rows


@contextmanager
def atomic_output(path, **kwargs):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp",
                                         delete=False, **kwargs) as stream:
            temporary = Path(stream.name)
            yield stream
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    with CATALOG.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        rebuild_catalog()


def rebuild_catalog():
    sources = {r[3]: r for r in tsv(WS / "vault_v2_sources.tsv") if len(r) >= 6}
    root_states = {}
    for r in tsv(WS / "vault_v2_roots.tsv"):
        if len(r) >= 6:
            root_states[r[2]] = {"state": r[5], "at": r[0], "path": r[1]}
    confirmed = {label for label, row in root_states.items()
                 if row["state"] == "ROOT_CLOUD_CONFIRMED"}
    version_store = VersionStore(WS)
    version_heads = (version_store.heads_doc()["heads"]
                     if version_store.heads_path.exists() else {})
    if version_store.heads_path.exists():
        confirmed &= set(version_heads)
    snapshot_proofs = {
        r[0]: r for r in tsv(WS / "workspace_snapshot_proofs.tsv")
        if len(r) >= 8 and r[7] == "PASS"
    }
    upload_sha = {r[1]: r[4] for r in tsv(WS / "upload_ledger.tsv") if len(r) >= 6 and r[5] == "CLOUD_CONFIRMED"}
    candidate_by_label = {}
    for r in tsv(WS / "queue_hostb_cold_verified_20260829.tsv"):
        if len(r) >= 3:
            candidate_by_label[r[0]] = ("hostb", r[1], r[0], None, r[2])
    for r in tsv(WS / "queue_hostb_manifest_expansion_20260829.tsv"):
        if len(r) >= 9:
            candidate_by_label[r[0]] = ("hostb", r[1], r[0], int(r[7]), r[8])
    for r in tsv(WS / "queue_mac.tsv"):
        if len(r) >= 3:
            label = next((k for k, v in sources.items() if v[2] == r[1]), Path(r[1]).name)
            candidate_by_label[label] = ("Mac", r[1], label, int(r[0]), r[2])
    # Sources is the append-only logical-location authority.  Queue files are
    # historical discovery inputs and may retain the pre-migration path forever;
    # they must never overwrite a newer source row for the same asset.
    for label, r in sources.items():
        candidate_by_label[label] = (r[1], r[2], label, int(r[4]), r[5])

    candidates = list(candidate_by_label.values())
    semantics = jsonl(SEMANTICS)
    semantic_by_asset = {str(row["cloud_asset_id"]): row for row in semantics
                         if row.get("cloud_asset_id")}
    semantic_by_path = {
        (str(row.get("host") or "").casefold(), str(row.get("path") or "")): row
        for row in semantics if row.get("path")
    }
    archive_sha = archive_fingerprints()

    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    rows = []
    manifest_rows = []
    remote_seen = remote_exists_batch(
        [path for machine, path, *_ in candidates if machine != "Mac"])
    for machine, path, label, queued_size, description in candidates:
        src = sources.get(label)
        size = int(src[4]) if src else queued_size
        if machine == "Mac":
            exists = Path(path).exists()
        elif path in remote_seen:
            exists = remote_seen[path]
        else:
            exists = remote_exists(path)
        cloud = label in confirmed
        root_state = root_states.get(label) or {}
        proof = snapshot_proofs.get(label)
        consistency_verified = bool(
            proof and len(proof) >= 11 and proof[3] == path and proof[9] and cloud
        )
        snapshot_verified = bool(consistency_verified)
        local_state = "replicated" if exists and cloud else "cloud_only" if cloud else "local"
        keywords = sorted(set(filter(None, (
            label, Path(path).name, description, "百度网盘", "密文仓", "冷资产",
            "tts-engine" if "engine-e" in path else None,
            "示例项目" if "示例项目" in path else None,
        ))))
        semantic = semantic_by_asset.get(label) or semantic_by_path.get(
            (str(machine).casefold(), path)
        ) or {}
        semantic_keywords = semantic.get("keywords_json") or "[]"
        if isinstance(semantic_keywords, str):
            try:
                semantic_keywords = json.loads(semantic_keywords)
            except json.JSONDecodeError:
                semantic_keywords = []
        keywords = sorted(set(keywords + [str(x) for x in semantic_keywords]))
        row = {
            "asset_id": label, "label": label, "machine": machine,
            "original_path": path, "description": description,
            "keywords": keywords, "size": size, "local_state": local_state,
            "cloud_state": "confirmed" if cloud else "pending",
            "catalog": str(CATALOG), "manifest": str(MANIFEST),
            "ledger": str(WS / "vault_v2_ledger.tsv"),
            "restore": f"{WS / 'cloud_asset_restore.py'} {label}",
            "indexed_at": now,
            "archived_at": root_state.get("at") if cloud else None,
            "snapshot_verified": snapshot_verified,
            "snapshot_sha256": proof[4] if snapshot_verified else None,
            "consistency_verified": consistency_verified,
            "consistency_fingerprint": proof[9] if consistency_verified else None,
            "archive_content_fingerprint": archive_sha.get(label),
            "current_version_id": (version_heads.get(label) or {}).get("version_id"),
            "previous_version_id": (version_heads.get(label) or {}).get("previous_version_id"),
            "content_fingerprint": semantic.get("content_fingerprint") or archive_sha.get(label),
            "semantic_revision": int(semantic.get("semantic_revision") or 0),
            "annotation_status": semantic.get("annotation_status") or "CURRENT",
            "semantic_summary": semantic.get("summary") or description,
            "semantic_keywords": semantic_keywords,
            "annotated_by": semantic.get("annotated_by"),
            "annotated_at": semantic.get("annotated_at"),
            "index_synced_at": semantic.get("index_synced_at"),
        }
        rows.append(row)
        if machine == "Mac" and (exists or cloud):
            manifest_rows.append((label, Path(path).name, str(size or ""), "file", upload_sha.get(path, "")))

    # v3 projection.  A v2 row keeps precedence only when it carries real v2 cloud
    # proof (cloud_state=confirmed).  A queue-derived, never-confirmed v2 placeholder
    # (e.g. a batch whose fixed-1GB stream was stopped by FUNCTION_V2_MIGRATION_HOLD)
    # must not hide the v3 proofs that actually exist for the same asset.
    confirmed_v2 = {row["asset_id"] for row in rows if row["cloud_state"] == "confirmed"}
    v3_rows = {row["asset_id"]: row for row in
               logical_vault_v3_rows(confirmed_v2, semantic_by_asset, now)}
    superseded = 0
    for index, row in enumerate(rows):
        if row["asset_id"] in v3_rows:
            replacement = v3_rows.pop(row["asset_id"])
            replacement["superseded_v2_placeholder"] = {
                "cloud_state": row["cloud_state"], "local_state": row["local_state"],
            }
            rows[index] = replacement
            superseded += 1
    rows.extend(v3_rows.values())
    if superseded or v3_rows:
        print(f"CATALOG_V3_PROJECTION superseded_v2_placeholders={superseded} "
              f"appended={len(v3_rows)}")

    with atomic_output(CATALOG, encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    with atomic_output(MANIFEST, encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["asset_id", "relative_path", "size", "type", "sha256_if_known"])
        w.writerows(manifest_rows)
    print(f"CATALOG_OK assets={len(rows)} confirmed={sum(r['cloud_state']=='confirmed' for r in rows)} cloud_only={sum(r['local_state']=='cloud_only' for r in rows)}")


if __name__ == "__main__":
    main()
