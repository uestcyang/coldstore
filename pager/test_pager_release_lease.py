#!/usr/bin/env python3
"""release_lease(): a producer lease must not keep a cloud-proven page HOT after the producer is done.

Incident note: asset-pool-v3 batch-0001 (~80GB, cloud-proven) stayed
KEEP_HOT because the pipeline's 8h "active production" lease was renewed 310 times
and then merely abandoned, leaving last_access at the last renewal.
"""
import os, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workspace_pager as wp


class ReleaseLease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.pg = wp.WorkspacePager(db_path=root / "pages.db", manifest_dir=root / "manifests",
                                    policy_config=dict(wp.load_policy()))
        self.path = "/home/user/asset-pool-v3/batch-9999"
        self.pg.touch("hostb", self.path, "asset-pool-v3 active production")

    def tearDown(self):
        self.tmp.cleanup()

    def row(self):
        key = self.pg.key("hostb", self.path)
        with self.pg.connect() as conn:
            return dict(conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone())

    def prove(self, archive_epoch):
        key = self.pg.key("hostb", self.path)
        with self.pg.connect() as conn:
            conn.execute("UPDATE pages SET local_present=1,cloud_verified=1,archive_epoch=? WHERE workspace_key=?",
                         (archive_epoch, key))

    def test_release_falls_back_to_archive_epoch_and_warm(self):
        old = time.time() - 30 * 86400
        self.prove(old)
        before = self.row()
        self.assertIsNotNone(before["lease_until"])
        r = self.pg.release_lease("hostb", self.path, "cloud pass")
        self.assertIsNone(r["lease_until"])
        self.assertEqual(r["state"], "WARM")
        self.assertAlmostEqual(r["last_access"], old, places=3)
        self.assertLess(r["last_access"], before["last_access"])

    def test_release_never_moves_access_forward(self):
        self.prove(time.time() + 3600)
        before = self.row()
        r = self.pg.release_lease("hostb", self.path, "cloud pass")
        self.assertEqual(r["last_access"], before["last_access"])
        self.assertIsNone(r["lease_until"])

    def test_release_without_evidence_keeps_access(self):
        before = self.row()
        r = self.pg.release_lease("hostb", self.path, "cloud pass")
        self.assertEqual(r["last_access"], before["last_access"])
        self.assertIsNone(r["lease_until"])
        self.assertEqual(r["state"], "HOT")

    def test_release_is_idempotent(self):
        self.prove(time.time() - 10 * 86400)
        a = self.pg.release_lease("hostb", self.path, "cloud pass")
        b = self.pg.release_lease("hostb", self.path, "cloud pass again")
        self.assertEqual((a["last_access"], a["state"], a["lease_until"]), (b["last_access"], b["state"], b["lease_until"]))

    def test_pinned_page_is_untouched(self):
        self.prove(time.time() - 10 * 86400)
        self.pg.set_pin("hostb", self.path, True, "pin")
        before = self.row()
        r = self.pg.release_lease("hostb", self.path, "cloud pass")
        self.assertEqual(r["last_access"], before["last_access"])
        self.assertEqual(r["lease_until"], before["lease_until"])

    def test_unknown_page_refused(self):
        with self.assertRaises(wp.PagerRefused):
            self.pg.release_lease("hostb", "/home/user/does-not-exist-xyz", "cloud pass")


if __name__ == "__main__":
    unittest.main()
