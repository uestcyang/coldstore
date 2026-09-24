#!/usr/bin/env python3
import fcntl
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import workspace_pager_cycle as cycle


class CycleTests(unittest.TestCase):
    def test_held_lock_does_not_launch_duplicate(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (root / 'archive.lock').open('a+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                spawn = mock.Mock()
                out = cycle.supervise('archive', root, spawn)
                self.assertEqual(out['status'], 'RUNNING')
                self.assertFalse(out['completed'])
                spawn.assert_not_called()

    def test_descriptor_remains_locked_in_child_after_launcher_closes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            child = []
            def spawn(cmd, **kwargs):
                p = subprocess.Popen(['python3', '-c', 'import time; time.sleep(20)'], **kwargs)
                child.append(p)
                return p
            try:
                out = cycle.supervise('pressure', root, spawn)
                self.assertEqual(out['status'], 'STARTED')
                with (root / 'pressure.lock').open('a+') as lock:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                for p in child:
                    p.terminate()
                    p.wait()

    def test_worker_records_failure_truthfully(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (root / 'archive.lock').open('a+') as lock:
                rc = cycle.worker('archive', lock.fileno(), root,
                    mock.Mock(return_value=subprocess.CompletedProcess([], 7)))
            self.assertEqual(rc, 7)
            self.assertEqual(json.loads((root/'archive.json').read_text())['status'], 'FAILED')

    def test_worker_records_success(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (root / 'archive.lock').open('a+') as lock:
                self.assertEqual(cycle.worker('archive', lock.fileno(), root,
                    mock.Mock(return_value=subprocess.CompletedProcess([], 0))), 0)
            self.assertTrue(json.loads((root/'archive.json').read_text())['completed'])

    def test_stale_running_is_recorded_before_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'archive.json').write_text('{"status":"RUNNING","pid":999999}')
            cycle.supervise('archive', root, mock.Mock(return_value=mock.Mock(pid=123)))
            self.assertEqual(json.loads((root/'archive.previous.json').read_text())['status'], 'INTERRUPTED')


if __name__ == '__main__':
    unittest.main()
