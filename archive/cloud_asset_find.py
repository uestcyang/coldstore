#!/usr/bin/env python3
import argparse
import gzip
import json
from pathlib import Path

WS = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description="Search Baidu cold assets by name, old path, or purpose")
    ap.add_argument("query")
    args = ap.parse_args()
    terms = args.query.casefold().split()
    hits = []
    for line in (WS / "cloud_asset_catalog.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        hay = json.dumps(row, ensure_ascii=False).casefold()
        if all(t in hay for t in terms):
            hits.append(row)
    manifest_hits = []
    mp = WS / "cloud_asset_manifest.tsv"
    if mp.exists():
        for line in mp.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            hay = line.casefold()
            if all(t in hay for t in terms):
                manifest_hits.append(line.split("\t")[:4])
    manifest_dir = WS / "manifests"
    for gz in sorted(manifest_dir.glob("*.jsonl.gz")) if manifest_dir.exists() else []:
        with gzip.open(gz, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if all(t in line.casefold() for t in terms):
                    row = json.loads(line)
                    manifest_hits.append([row["asset_id"], row["relative_path"], str(row["size"]), "file"])
                    if len(manifest_hits) >= 100:
                        break
    for r in hits:
        print(f"ASSET\t{r['asset_id']}\t{r['local_state']}\t{r['cloud_state']}\t{r['original_path']}\t{r['description']}")
    for r in manifest_hits[:100]:
        print("FILE\t" + "\t".join(r))
    if not hits and not manifest_hits:
        raise SystemExit("NOT_FOUND")


if __name__ == "__main__":
    main()
