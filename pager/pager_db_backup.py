#!/usr/bin/env python3
"""Back up the page table's authoritative rows, not its rebuildable index.

Measured <date>: the table is 1.26GB on the Mac and 3.47GB on the hostb, yet
the rows that actually decide whether local bytes may be deleted -- ``pages``,
``pager_meta``, ``asset_file_sources`` -- serialise to 0.98MB.  The remaining
99.9% is ``asset_files`` plus its FTS shadow tables: a search index over 1.03M
cloud file paths that ``WorkspacePager._sync_asset_files`` regenerates from the
21MB manifest directory, keyed on each manifest's mtime/size.

So a full-file copy costs ~1280x the data it protects, which in practice means
backups are taken rarely and pruned aggressively -- exactly the wrong trade for
the one table whose corruption is unrecoverable.  A slim dump is cheap enough to
take before every risky mutation and keep many generations of.

Restore is deliberately two steps: load the rows, then run a pager sync to
rebuild the index.  Skipping the second step leaves ``cloud_asset_find`` blind,
so the restore path prints the command rather than assuming it was run.
"""
from __future__ import annotations

import argparse
import gzip
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

DB = Path.home() / ".coldstore/state/workspace_pages.db"
BACKUP_DIR = Path.home() / ".coldstore/cron/pager_backups"
# Authority = rows a human decision or an irreversible delete depends on.
# asset_file_sources is small and carries the manifest mtime/size fingerprints,
# so keeping it lets the rebuild skip unchanged manifests instead of redoing all.
AUTHORITY_TABLES = ("pages", "pager_meta", "asset_file_sources")


def _literal(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, bytes):
        return "X'" + value.hex() + "'"
    return "'" + str(value).replace("'", "''") + "'"


def dump_slim(db: Path, out: Path) -> dict:
    """Serialise the authoritative tables to a gzipped SQL script."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    counts, started = {}, time.time()
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        fh.write(f"-- pager slim backup from {db}\n-- generated {time.time():.0f}\n")
        fh.write("BEGIN;\n")
        for table in AUTHORITY_TABLES:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
            if not cols:
                counts[table] = 0
                continue
            fh.write(f"DELETE FROM {table};\n")
            n = 0
            for row in conn.execute(f"SELECT * FROM {table}"):
                fh.write(f"INSERT INTO {table} VALUES({','.join(_literal(v) for v in row)});\n")
                n += 1
            counts[table] = n
        fh.write("COMMIT;\n")
    conn.close()
    return {"tables": counts, "bytes": out.stat().st_size,
            "seconds": round(time.time() - started, 2)}


def restore_slim(db: Path, script: Path) -> dict:
    """Load a slim dump into an existing database file.

    The target must already exist: the dump carries rows, not schema, because a
    schema snapshot would silently reintroduce whatever migrations the live file
    has since applied.
    """
    if not db.is_file():
        raise SystemExit(f"REFUSE_RESTORE_TARGET_MISSING {db}")
    opener = gzip.open if script.suffix == ".gz" else open
    with opener(script, "rt", encoding="utf-8") as fh:
        sql = fh.read()
    conn = sqlite3.connect(db, timeout=600)
    conn.executescript(sql)
    conn.commit()
    counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in AUTHORITY_TABLES}
    conn.close()
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DB)
    ap.add_argument("--label", default="manual")
    ap.add_argument("--full", action="store_true",
                    help="copy the whole file including the rebuildable index")
    ap.add_argument("--restore", type=Path, help="load a slim dump into --db")
    args = ap.parse_args()

    if args.restore:
        counts = restore_slim(args.db, args.restore)
        print("RESTORED " + " ".join(f"{k}={v}" for k, v in counts.items()))
        print("NEXT rebuild the search index:  ws page sync")
        return 0

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if args.full:
        out = BACKUP_DIR / f"workspace_pages.db.bak-{args.label}-{stamp}"
        shutil.copy2(args.db, out)
        print(f"FULL {out} bytes={out.stat().st_size}")
        return 0
    out = BACKUP_DIR / f"pages-slim-{args.label}-{stamp}.sql.gz"
    info = dump_slim(args.db, out)
    saved = args.db.stat().st_size - info["bytes"]
    print(f"SLIM {out} bytes={info['bytes']} seconds={info['seconds']} "
          + " ".join(f"{k}={v}" for k, v in info["tables"].items())
          + f" saved_vs_full={saved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
