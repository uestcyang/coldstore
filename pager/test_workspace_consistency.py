#!/usr/bin/env python3
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

import workspace_consistency as wc


class WorkspaceConsistencyTests(unittest.TestCase):
    def test_plain_tree_passes(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "a.txt").write_text("ok")
            proof = wc.inspect_workspace(td)
            self.assertEqual(proof["verdict"], "PASS")
            self.assertEqual(len(proof["fingerprint"]), 64)

    def _seed_db(self, td):
        db = Path(td, "state.db")
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE t(x)")
            conn.execute("INSERT INTO t VALUES(1)")
        return db

    def test_clean_sqlite_passes(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed_db(td)
            proof = wc.inspect_workspace(td)
            self.assertEqual(proof["sqlite"][0]["quick_check"], "ok")
            self.assertEqual(proof["sqlite"][0]["sidecars"], "absent")

    def test_dirty_wal_or_journal_still_refuses(self):
        # 判据 <date> 收窄后,「真有未落盘数据」这一侧必须一个字都不放宽。
        for suffix, magic in (("-wal", b"\x37\x7f\x06\x82"),
                              ("-journal", b"\xd9\xd5\x05\xf9")):
            with self.subTest(sidecar=suffix), tempfile.TemporaryDirectory() as td:
                db = self._seed_db(td)
                Path(str(db) + suffix).write_bytes(magic + b"\0" * 64)
                with self.assertRaisesRegex(wc.ConsistencyRefused, "UNCHECKPOINTED"):
                    wc.inspect_workspace(td)

    def test_empty_sidecars_pass_and_are_disclosed(self):
        # firecrawl 现场:0 字节 -wal + 32KB -shm、无进程持有。旧判据按「文件存在」
        # 恒拒,把 3.6GB 的页永久挡在归档外(连拒 172 次)。放行,但证据必须如实写明
        # 放行的是空 sidecar 而不是「没有 sidecar」,否则复盘时看不出区别。
        cases = (
            ("空 wal + shm", (("-wal", b""), ("-shm", b"\0" * 32768))),
            ("仅 shm", (("-shm", b"\0" * 32768),)),
            ("空 journal", (("-journal", b""),)),
        )
        for tag, files in cases:
            with self.subTest(case=tag), tempfile.TemporaryDirectory() as td:
                db = self._seed_db(td)
                for suffix, blob in files:
                    Path(str(db) + suffix).write_bytes(blob)
                proof = wc.inspect_workspace(td)
                self.assertEqual(proof["verdict"], "PASS")
                self.assertTrue(proof["sqlite"][0]["sidecars"].startswith("empty:"),
                                proof["sqlite"][0]["sidecars"])

    def test_unsupported_database_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "CURRENT").write_text("MANIFEST-000001\n")
            (root / "MANIFEST-000001").touch()
            with self.assertRaisesRegex(wc.ConsistencyRefused, "UNSUPPORTED_DATABASE"):
                wc.inspect_workspace(td)

    def test_git_must_be_root_and_clean(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td, "repo")
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "tracked").write_text("one")
            subprocess.run(["git", "-C", str(repo), "add", "tracked"], check=True)
            subprocess.run([
                "git", "-C", str(repo), "-c", "user.name=unit",
                "-c", "user.email=unit@example.invalid", "commit", "-qm", "init",
            ], check=True)
            self.assertEqual(wc.inspect_workspace(repo)["git"][0]["status"], "clean")
            with self.assertRaisesRegex(wc.ConsistencyRefused, "PARTIAL_ROOT"):
                wc.inspect_workspace(repo / "tracked")
            (repo / "tracked").write_text("dirty")
            with self.assertRaisesRegex(wc.ConsistencyRefused, "GIT_DIRTY"):
                wc.inspect_workspace(repo)

    def test_untracked_gitignored_subtree_of_a_dirty_repo_passes(self):
        # <date> real bug: 示例项目/示例产线/产物/q* and
        # .agent-agent-f/research/* are fully .gitignore'd data trees living
        # inside otherwise-dirty source-controlled repos. The old check
        # refused them purely because they weren't the repo's own toplevel,
        # even though nothing under them is git-tracked -- deleting/archiving
        # them can never disturb HEAD. That blocked the entire cold-archive
        # backlog on a false-positive. A subtree with zero tracked paths must
        # pass with an empty git proof, independent of the rest of the repo's
        # (dirty, untracked-elsewhere) state.
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td, "repo")
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "tracked.py").write_text("code")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.py"], check=True)
            subprocess.run([
                "git", "-C", str(repo), "-c", "user.name=unit",
                "-c", "user.email=unit@example.invalid", "commit", "-qm", "init",
            ], check=True)
            (repo / ".gitignore").write_text("/data/*\n")
            data = repo / "data" / "q13385348"
            data.mkdir(parents=True)
            (data / "output.mp4").write_bytes(b"fake video bytes")
            # Repo has an untracked .gitignore itself, so the *whole repo* is
            # not clean -- proving the subtree doesn't need repo-wide status.
            self.assertTrue(
                subprocess.run(
                    ["git", "-C", str(repo), "status", "--porcelain"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
            )
            proof = wc.inspect_workspace(data)
            self.assertEqual(proof["verdict"], "PASS")
            self.assertEqual(proof["git"], [])

    def test_untracked_subtree_with_one_tracked_file_still_refuses(self):
        # The relaxation above must stay narrow: if even one file underneath
        # target is git-tracked, partial-tree deletion is still unprovable
        # and must keep refusing exactly like before.
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td, "repo")
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            sub = repo / "mixed"
            sub.mkdir()
            (sub / "tracked.py").write_text("code")
            (sub / "scratch.bin").write_bytes(b"data")
            subprocess.run(["git", "-C", str(repo), "add", "mixed/tracked.py"],
                           check=True)
            subprocess.run([
                "git", "-C", str(repo), "-c", "user.name=unit",
                "-c", "user.email=unit@example.invalid", "commit", "-qm", "init",
            ], check=True)
            with self.assertRaisesRegex(wc.ConsistencyRefused, "PARTIAL_ROOT"):
                wc.inspect_workspace(sub)


class ProcessReferenceTests(unittest.TestCase):
    def probe(self, args, *, cwd='/home/test', executable='/usr/bin/python3', maps=''):
        import workspace_archive_remote as remote
        td = tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        proc = Path(td.name); p = proc / '123'; p.mkdir()
        (p/'cmdline').write_bytes(b'\0'.join(x.encode() for x in args))
        (p/'cwd').symlink_to(cwd); (p/'exe').symlink_to(executable)
        (p/'maps').write_text(maps)
        return remote.process_refs('/home/test/service', proc, own_pid=999)

    def test_closed_python_source_still_protected(self):
        self.assertTrue(self.probe(['python3','/home/test/service/app.py'])['hits'])

    def test_relative_script_and_config_paths_protected(self):
        for arg in ['service/app.py','--config=/home/test/service/config.json']:
            self.assertTrue(self.probe(['python3',arg])['hits'])

    def test_cwd_executable_maps_protected(self):
        for kw in [{'cwd':'/home/test/service'}, {'executable':'/home/test/service/bin/python'},
                   {'maps':'001 002 003 004 005 /home/test/service/library.so'}]:
            self.assertTrue(self.probe(['python3'],**kw)['hits'])

    def test_space_in_path_is_not_ignored(self):
        self.assertTrue(self.probe(['python3','/home/test/service/app name.py'])['hits'])

    def test_sibling_and_unrelated_process_allow(self):
        d=self.probe(['python3','/home/test/service-old/app.py'])
        self.assertEqual(d['checked'],1);self.assertEqual(d['hits'],[])

    def test_incomplete_proc_scan_fails_closed(self):
        import workspace_archive_remote as remote
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'123';p.mkdir();(p/'cmdline').write_bytes(b'python3')
            with self.assertRaisesRegex(wc.ConsistencyRefused,'RACE'):
                remote.process_refs('/home/test/service',Path(td),own_pid=999)


if __name__ == "__main__":
    unittest.main(verbosity=2)
