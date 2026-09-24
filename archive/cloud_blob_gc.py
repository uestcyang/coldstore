#!/usr/bin/env python3
"""Exact GC for blobs referenced only by superseded vault versions."""
import argparse
import csv
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from vault_v2_versions import VersionStore

WS = Path(__file__).resolve().parent
CLOUD_BASE = os.environ.get("COLDSTORE_CLOUD_BASE", "/ColdArchive")
LEDGER = WS / "vault_v2_blob_gc.tsv"


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    candidates = VersionStore(WS).gc_candidates()
    if not args.execute:
        print(json.dumps({"candidate_count": len(candidates), "candidates": candidates},
                         ensure_ascii=False, sort_keys=True))
        return
    busy = subprocess.run(["pgrep", "-f", "[v]ault_v2_stream.py"],
                          stdout=subprocess.PIPE, text=True)
    if busy.returncode == 0:
        raise SystemExit("REFUSE_GC_VAULT_WRITER_BUSY")
    for item in candidates:
        # Recompute before every irreversible operation; a concurrent head
        # switch can therefore only shrink, never broaden, the deletion set.
        current = {row["blob_id"]: row for row in VersionStore(WS).gc_candidates()}
        if item["blob_id"] not in current:
            raise SystemExit("REFUSE_GC_CANDIDATE_CHANGED")
        cloud_path = f"{CLOUD_BASE}/{item['cloud_relative_path']}"
        result = subprocess.run([
            str(WS / "baidu_client_delete.py"), cloud_path,
            "--expected-size", str(item["encrypted_bytes"]), "--execute",
        ], text=True, capture_output=True)
        if result.returncode or "RECYCLE_PASS" not in result.stdout:
            raise SystemExit("REFUSE_GC_DELETE_FAILED " + (result.stdout + result.stderr)[-2000:])
        with LEDGER.open("a", encoding="utf-8", newline="") as handle:
            csv.writer(handle, delimiter="\t", lineterminator="\n").writerow([
                now_iso(), item["blob_id"], item["encrypted_bytes"],
                item["encrypted_sha256"], "RECYCLE_CONFIRMED",
                json.dumps(item["superseded_versions"], separators=(",", ":")),
            ])
            handle.flush(); os.fsync(handle.fileno())
    print(f"BLOB_GC_PASS deleted={len(candidates)}")


if __name__ == "__main__":
    main()
