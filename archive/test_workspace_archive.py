#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

import workspace_archive as wa


class WorkspaceArchiveTests(unittest.TestCase):
    def test_broad_roots_are_refused(self):
        for path in ("/", "/Users/user", "relative"):
            with self.assertRaises(wa.ArchiveRefused):
                wa.validate_target("mac", path)

    def test_label_is_stable_and_path_specific(self):
        one = wa.asset_label("hostb", "/home/user/project/tool")
        self.assertEqual(one, wa.asset_label("hostb", "/home/user/project/tool"))
        self.assertNotEqual(one, wa.asset_label("hostb", "/home/user/other/tool"))

    def test_snapshot_is_deterministic_and_detects_change(self):
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            root = Path(td)
            (root / "a").write_bytes(b"one")
            first = wa._snapshot_local(root)
            self.assertEqual(first, wa._snapshot_local(root))
            (root / "a").write_bytes(b"two-two")
            self.assertNotEqual(first, wa._snapshot_local(root))

    def test_symlink_root_is_refused(self):
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            root = Path(td)
            target = root / "target"; target.mkdir()
            link = root / "link"; link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(wa.ArchiveRefused):
                wa._snapshot_local(link)

    # --- 实时冷度(<date>):require_cold_page 只看 last_access,而它取自
    # HANDOFF.md 的 mtime 且注册后冻结。实测 hostb 上 qcln* 产物目录当时还在
    # 被 qbank 产线写入,库里 tree_recent 仍是 3.3 小时前探的 0(冷)。归档器照它
    # 上传 = 传一个正在变的树,快照校验必失败,白烧 4.4MB/s 的上行。
    def _probe(self, answer):
        def fake(host, path, window_days):
            self.assertGreater(window_days, 0)
            return answer
        return fake

    def test_live_tree_is_refused_even_when_last_access_is_ancient(self):
        with self.assertRaises(wa.ArchiveRefused) as ctx:
            wa.assert_tree_not_live("hostb", "/home/user/x", 3, probe=self._probe(1))
        self.assertIn("REFUSE_PAGE_TREE_LIVE", str(ctx.exception))

    def test_cold_tree_passes(self):
        wa.assert_tree_not_live("hostb", "/home/user/x", 3, probe=self._probe(0))

    def test_unprobeable_tree_fails_closed(self):
        # 探测不了不等于冷:ssh 超时/权限问题一律拒绝,不许赌
        with self.assertRaises(wa.ArchiveRefused) as ctx:
            wa.assert_tree_not_live("hostb", "/home/user/x", 3, probe=self._probe(None))
        self.assertIn("REFUSE_PAGE_LIVENESS_UNKNOWN", str(ctx.exception))

    def test_probe_detects_recent_write_on_local_tree(self):
        # 真实文件系统判据,不是 mock:刚写的文件必须被判活跃
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            root = Path(td)
            (root / "fresh.txt").write_text("just written")
            self.assertEqual(wa.probe_tree_recent(wa.SELF_HOST, str(root), 3), 1)

    def test_probe_reports_cold_for_backdated_tree(self):
        import os, time
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            root = Path(td)
            old = root / "old.txt"
            old.write_text("stale")
            past = time.time() - 40 * 86400
            os.utime(old, (past, past))
            os.utime(root, (past, past))
            self.assertEqual(wa.probe_tree_recent(wa.SELF_HOST, str(root), 3), 0)

    def test_probe_missing_path_is_unknown_not_cold(self):
        self.assertIsNone(wa.probe_tree_recent("mac", "/Users/user/__no_such__", 3))


if __name__ == "__main__":
    unittest.main()
