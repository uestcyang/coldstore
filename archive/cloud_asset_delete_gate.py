#!/usr/bin/env python3
"""Deletion preflight. This script never deletes; it only permits or refuses.

Operator policy "trust-the-cloud": every check that
needed a Baidu download-back is gone.  What remains is ledger-local:
catalogue row, cloud-confirmed current head, whole-root head, archive-time
snapshot proof, per-version file manifest, semantic anchor, three-copy metadata.
"""
import argparse
import csv
import json
from pathlib import Path

from vault_v2_versions import VersionRefused, VersionStore
from cloud_asset_evict_once import file_manifest_identity

WS = Path(__file__).resolve().parent


def ids(path):
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as f:
        return {r[0] for r in csv.reader(f, delimiter="\t") if r and not r[0].startswith("#")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("asset_id")
    args = ap.parse_args()
    rows = [json.loads(x) for x in (WS / "cloud_asset_catalog.jsonl").read_text(encoding="utf-8").splitlines()]
    row = next((x for x in rows if x["asset_id"] == args.asset_id), None)
    semantic_ids = ids(WS / "cloud_asset_semantic_anchors.tsv")
    has_manifest = args.asset_id in ids(WS / "cloud_asset_manifest.tsv") or (
        (WS / "manifests" / f"{args.asset_id}.files0.gz").is_file()
        and (WS / "manifests" / f"{args.asset_id}.jsonl.gz").is_file()
    )
    version_store = VersionStore(WS)
    version = None
    head_root = None
    try:
        head_rows = version_store.head_rows(args.asset_id) if version_store.heads_path.exists() else []
        current_head = True if head_rows else not version_store.heads_path.exists()
        head = version_store.heads_doc().get("heads", {}).get(args.asset_id, {})
        version = head.get("version_id")
        head_root = head.get("root")
    except VersionRefused:
        head_rows = []
        current_head = False
    manifest_identity = file_manifest_identity(args.asset_id, version) if version else None
    has_manifest = has_manifest or bool(manifest_identity)
    with (WS / "cloud_asset_three_copy.tsv").open(encoding="utf-8") as stream:
        version_copy = any(manifest_identity and len(record) >= 7 and record[0] == args.asset_id
                           and record[5] == version and record[6] == manifest_identity
                           for record in csv.reader(stream, delimiter="\t"))
    checks = {
        "catalog": row is not None,
        "cloud_confirmed": bool(row and row["cloud_state"] == "confirmed"),
        "file_manifest": has_manifest,
        "version_file_manifest": bool(manifest_identity),
        "semantic_anchor": args.asset_id in semantic_ids or "*" in semantic_ids,
        "restore_parts": False,
        "current_version_head": current_head,
        "catalog_head_is_current": bool(version and row and row.get("current_version_id") == version),
        "whole_root_head": bool(row and head_root and head_root == row.get("original_path")),
        "archive_snapshot_proof": bool(row and row.get("snapshot_verified")),
        "three_copy_current_version": version_copy,
        "three_copy_sync": args.asset_id in ids(WS / "cloud_asset_three_copy.tsv"),
    }
    if head_rows:
        checks["restore_parts"] = True
    else:
        with (WS / "vault_v2_ledger.tsv").open(encoding="utf-8") as f:
            checks["restore_parts"] = any(
                len(r) == 12 and r[2] == args.asset_id and r[11] == "CLOUD_CONFIRMED"
                for r in csv.reader(f, delimiter="\t")
            )
    for k, v in checks.items():
        print(f"{k}={'PASS' if v else 'FAIL'}")
    if not all(checks.values()):
        raise SystemExit("DELETE_REFUSED")
    print(f"DELETE_PREFLIGHT_PASS asset={args.asset_id}; deletion still requires explicit user authorization")


if __name__ == "__main__":
    main()
