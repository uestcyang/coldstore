#!/usr/bin/env python3
"""Round-trip tests for the slim page-table backup."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

import pager_db_backup as b


SCHEMA = """
CREATE TABLE pages(workspace_key TEXT PRIMARY KEY, host TEXT, path TEXT,
                   state TEXT, pinned INTEGER, local_present INTEGER, note TEXT);
CREATE TABLE pager_meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE asset_file_sources(source_path TEXT PRIMARY KEY, mtime_ns INTEGER,
                                size_bytes INTEGER);
CREATE TABLE asset_files(source_path TEXT, relative_path TEXT);
"""


class SlimBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "pages.db"
        conn = sqlite3.connect(self.db)
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?)",
                     ("hostb|/home/user/x", "hostb", "/home/user/x",
                      "WARM", 0, 1, "it's \"quoted\""))
        conn.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?)",
                     ("mac|/Users/user/y", "mac", "/Users/user/y",
                      "COLD", 1, 0, None))
        conn.execute("INSERT INTO pager_meta VALUES('schema','7')")
        conn.execute("INSERT INTO asset_file_sources VALUES('/m/a.jsonl.gz',123,456)")
        # index rows deliberately excluded from the slim dump
        conn.executemany("INSERT INTO asset_files VALUES(?,?)",
                         [("/m/a.jsonl.gz", f"f{i}") for i in range(500)])
        conn.commit(); conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _rows(self, table):
        conn = sqlite3.connect(self.db)
        out = list(conn.execute(f"SELECT * FROM {table} ORDER BY 1"))
        conn.close()
        return out

    def test_roundtrip_restores_authority_rows_exactly(self):
        before = self._rows("pages")
        out = self.root / "dump.sql.gz"
        b.dump_slim(self.db, out)
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM pages"); conn.commit(); conn.close()
        self.assertEqual(self._rows("pages"), [])
        b.restore_slim(self.db, out)
        self.assertEqual(self._rows("pages"), before)

    def test_quotes_and_nulls_survive(self):
        out = self.root / "dump.sql.gz"
        b.dump_slim(self.db, out)
        b.restore_slim(self.db, out)
        rows = {r[0]: r for r in self._rows("pages")}
        self.assertEqual(rows["hostb|/home/user/x"][6], "it's \"quoted\"")
        self.assertIsNone(rows["mac|/Users/user/y"][6])

    def test_index_table_is_not_dumped(self):
        out = self.root / "dump.sql.gz"
        info = b.dump_slim(self.db, out)
        self.assertNotIn("asset_files", info["tables"])
        import gzip
        text = gzip.open(out, "rt", encoding="utf-8").read()
        self.assertNotIn("INSERT INTO asset_files ", text)
        self.assertIn("INSERT INTO pages", text)

    def test_restore_is_idempotent(self):
        out = self.root / "dump.sql.gz"
        b.dump_slim(self.db, out)
        b.restore_slim(self.db, out)
        first = self._rows("pages")
        b.restore_slim(self.db, out)
        self.assertEqual(self._rows("pages"), first, "二次恢复不得产生重复行")

    def test_restore_refuses_missing_target(self):
        out = self.root / "dump.sql.gz"
        b.dump_slim(self.db, out)
        with self.assertRaises(SystemExit):
            b.restore_slim(self.root / "absent.db", out)

    def test_slim_dump_is_far_smaller_than_the_file(self):
        out = self.root / "dump.sql.gz"
        info = b.dump_slim(self.db, out)
        self.assertLess(info["bytes"], self.db.stat().st_size,
                        "slim dump 必须显著小于整库")


if __name__ == "__main__":
    unittest.main()
