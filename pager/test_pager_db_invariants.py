#!/usr/bin/env python3
"""Assertions against the *live* page table, not a fixture.

Rationale: the page table is the single authority deciding which local bytes may
be deleted.  Every bug found on <date> was a state combination that no unit
test could see, because unit tests build their own fixtures.  These checks read
production and fail the daily regression the moment the real table drifts into a
contradictory state.

Each invariant below corresponds to a defect that actually occurred; none is
hypothetical.
"""
from __future__ import annotations

import os
import sqlite3
import unittest

DB = os.path.expanduser("~/.coldstore/state/workspace_pages.db")


class PagerDbInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(DB):
            raise unittest.SkipTest(f"page table absent: {DB}")
        cls.conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        cls.conn.row_factory = sqlite3.Row

    def _violations(self, where, limit=5):
        rows = list(self.conn.execute(
            f"SELECT host,path,state,pinned,local_present,cloud_verified "
            f"FROM pages WHERE {where} LIMIT {limit}"))
        total = self.conn.execute(
            f"SELECT COUNT(*) FROM pages WHERE {where}").fetchone()[0]
        detail = "; ".join(f"{r['state']}/{r['host']}:{r['path']}" for r in rows)
        return total, detail

    def test_no_pin_without_local_copy(self):
        """<date>: 13 rows were pinned while their bytes lived only in the
        vault.  ``sync`` set state=PINNED from a path-only rule while ``plan``
        classified the same rows KEEP_COLD, and a later fault-in would have made
        the tree permanently un-evictable."""
        total, detail = self._violations("pinned=1 AND local_present=0")
        self.assertEqual(total, 0, f"pinned but not local ({total}): {detail}")

    def test_cold_rows_are_cloud_verified(self):
        """COLD means the local copy may be deleted.  Asserting it without cloud
        confirmation is the one combination that loses data outright."""
        total, detail = self._violations("state='COLD' AND cloud_verified=0")
        self.assertEqual(total, 0, f"COLD without cloud proof ({total}): {detail}")

    def test_evicted_rows_carry_an_asset_id(self):
        """Without the id the bytes are unreachable: restore is keyed by it."""
        total, detail = self._violations(
            "local_present=0 AND cloud_verified=1 AND cloud_asset_id IS NULL")
        self.assertEqual(total, 0, f"evicted without asset id ({total}): {detail}")

    def test_host_values_are_normalised(self):
        """A raw hostname leaked in once and silently landed those rows in the
        EXTERNAL pool, i.e. outside paging altogether."""
        total, detail = self._violations("host NOT IN ('mac','hostb')")
        self.assertEqual(total, 0, f"non-normalised host ({total}): {detail}")

    def test_storage_pool_matches_host(self):
        """Only the hostb volume is managed; anything else must not be."""
        total, detail = self._violations(
            "(host!='hostb' AND storage_pool!='EXTERNAL') "
            "OR (host='hostb' AND storage_pool='EXTERNAL')")
        self.assertEqual(total, 0, f"pool/host mismatch ({total}): {detail}")


if __name__ == "__main__":
    unittest.main()
