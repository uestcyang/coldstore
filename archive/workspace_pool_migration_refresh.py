#!/usr/bin/env python3
"""Bind approved migration entries to persisted one-time restore evidence."""
import csv
import json
import os
import tempfile
from pathlib import Path

WS = Path(__file__).resolve().parent
MANIFEST = WS / "workspace_pool_migration_manifest.json"


def evidence():
    latest = {}
    path = WS / "cloud_asset_restore_tests.tsv"
    if not path.exists():
        return latest
    with path.open(encoding="utf-8") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if (len(row) >= 5
                    and row[2] == "baidu_native_download_decrypt_tar_source_match"
                    and row[3] == "PASS"):
                values = dict(
                    item.split("=", 1) for item in row[4].split(";") if "=" in item
                )
                fingerprint = values.get("content_fingerprint_v2", "")
                if len(fingerprint) == 64:
                    latest[row[0]] = fingerprint
    return latest


def main():
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if doc.get("schema_version") != 1:
        raise SystemExit("REFUSE_MIGRATION_MANIFEST_SCHEMA")
    catalog = {
        row["asset_id"]: row
        for row in (
            json.loads(line) for line in
            (WS / "cloud_asset_catalog.jsonl").read_text(encoding="utf-8").splitlines()
        )
    }
    proofs = evidence()
    ready, pending = [], []
    for row in doc.get("entries", []):
        asset = catalog.get(row.get("asset_id"))
        if (not asset or asset.get("original_path") != row.get("source")
                or asset.get("cloud_state") != "confirmed"):
            row["expected_content_fingerprint"] = ""
            pending.append(row.get("asset_id"))
            continue
        fingerprint = proofs.get(row["asset_id"], "")
        row["expected_content_fingerprint"] = fingerprint
        (ready if fingerprint else pending).append(row["asset_id"])
    descriptor, raw = tempfile.mkstemp(prefix=".pool-manifest.", suffix=".tmp", dir=WS)
    tmp = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, MANIFEST)
    finally:
        tmp.unlink(missing_ok=True)
    print(json.dumps({"ready": ready, "pending": pending},
                     ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
