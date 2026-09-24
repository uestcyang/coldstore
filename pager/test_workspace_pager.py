#!/usr/bin/env python3
import gzip
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest import mock
import sys
from pathlib import Path

import workspace_pager as wp
import workspace_archive_remote as remote_archive


class WorkspacePagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "pages.db"
        self.ws = self.root / "workspace"
        self.ws.mkdir()
        self.manifests = self.root / "manifests"
        self.manifests.mkdir()
        self.pager = wp.WorkspacePager(self.db, manifest_dir=self.manifests)

    def tearDown(self):
        self.tmp.cleanup()

    def test_readonly_alerts_survive_writer_lock_without_changing_state(self):
        self.pager.sync(self.record(), [], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET state='WARM',pinned=1,storage_pool='MANAGED'")
        before = self.pager.status()["rows"]
        with self.pager.connect() as writer:
            writer.execute('BEGIN IMMEDIATE')
            reader = wp.WorkspacePager(self.db, manifest_dir=self.manifests, read_only=True)
            disk = {"managed": {"total": 1000, "used": 920, "free": 80},
                    "isolated": {"total": 500, "used": 100, "free": 400}}
            self.assertTrue(reader.alerts(disk_stats=disk))
            self.assertEqual(reader.status()["rows"], before)
            self.assertIsNone(writer.execute(
                "SELECT value_json FROM pager_meta WHERE key='managed_eviction_active'").fetchone())
            writer.rollback()
        self.assertEqual(self.pager.status()["rows"], before)

    def test_readonly_connection_enforces_write_rejection(self):
        reader = wp.WorkspacePager(self.db, manifest_dir=self.manifests, read_only=True)
        with reader.connect() as conn, self.assertRaises(sqlite3.OperationalError):
            conn.execute("INSERT INTO pager_meta VALUES('synthetic','true',0)")

    def test_readonly_missing_database_does_not_create_paths(self):
        missing = self.root / 'not-created/pages.db'
        reader = wp.WorkspacePager(missing, read_only=True)
        with self.assertRaises(sqlite3.OperationalError):
            reader.connect()
        self.assertFalse(missing.parent.exists())

    def test_disk_sample_reuses_exact_pool_mounts_and_rejects_stale_or_invalid(self):
        import copy
        sample = {'host': 'hostb', 'observed_at': 100,
                  'disks': [{'mount': '/', 'total': 1000, 'used': 920, 'free': 80},
                            {'mount': '/data', 'total': 500, 'used': 100, 'free': 400}]}
        policy = {'managed_mount': '/', 'isolation_mount': '/data'}
        self.assertEqual(wp.disk_stats_from_sample(sample, policy, now=110)['managed']['free'], 80)
        with self.assertRaises(wp.PagerRefused):
            wp.disk_stats_from_sample(sample, policy, now=126)
        with self.assertRaises(wp.PagerRefused):
            wp.disk_stats_from_sample(sample, policy, now=99)
        invalid = copy.deepcopy(sample)
        invalid['disks'][0]['free'] = 2000
        with self.assertRaises(wp.PagerRefused):
            wp.disk_stats_from_sample(invalid, policy, now=110)
        invalid = copy.deepcopy(sample)
        invalid['disks'][1]['mount'] = '/'
        with self.assertRaises(wp.PagerRefused):
            wp.disk_stats_from_sample(invalid, policy, now=110)

    def test_alert_command_does_not_load_indexes_or_cloud_assets(self):
        import ast
        import contextlib
        import io
        from types import SimpleNamespace
        source = Path(__file__).with_name('ws')
        tree = ast.parse(source.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'cmd_page')
        module = mock.Mock()
        module.WorkspacePager.return_value.alerts.return_value = []
        module.load_assets.side_effect = AssertionError('unexpected asset load')
        index = mock.Mock(side_effect=AssertionError('unexpected index load'))
        namespace = {'pager': module, 'load_index': index, 'json': json}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(namespace['cmd_page'](SimpleNamespace(page_cmd='alerts', json=True)), 0)
        module.WorkspacePager.assert_called_once_with(read_only=True)
        module.load_assets.assert_not_called()
        index.assert_not_called()

    def record(self):
        return {"mac|" + str(self.ws): {
            "host": "mac", "path": str(self.ws), "mtime": time.time() - 20 * 86400,
        }}

    def probed_cold(self):
        """Record 'filesystem probe says no recent writes' for every page.

        <date> liveness gate: last_access is seeded from HANDOFF.md's mtime and
        then frozen, so it cannot tell a genuinely cold tree from a busy one whose
        HANDOFF is stale.  plan() now fails closed and refuses to archive or evict
        without a positive probe, so tests asserting those two actions must supply
        that evidence explicitly.
        """
        with self.pager.connect() as conn:
            conn.execute(
                "UPDATE pages SET tree_recent=0,tree_probed_at=?,tree_probe_days=?",
                (time.time(), self.pager.policy.get("liveness_window_days")
                 or self.pager.policy.get("hot_days", 3)))

    def test_liveness_probe_reads_real_filesystem_mtimes(self):
        """The probe must answer from the filesystem, not from HANDOFF metadata."""
        live = self.root / "livetree"
        (live / "sub").mkdir(parents=True)
        (live / "sub" / "fresh.txt").write_text("x")
        cold = self.root / "coldtree"
        cold.mkdir()
        old_file = cold / "stale.txt"
        old_file.write_text("x")
        old = time.time() - 400 * 86400
        os.utime(old_file, (old, old))
        os.utime(cold, (old, old))
        answers = self.pager._probe_tree_recent(
            wp._self_host(), [str(live), str(cold), str(self.root / "missing")], 15)
        self.assertEqual(answers[str(live)], 1)
        self.assertEqual(answers[str(cold)], 0)
        self.assertIsNone(answers[str(self.root / "missing")])

    def test_refresh_tree_liveness_persists_and_unblocks_archiving(self):
        """A cold tree stays blocked until probed, then becomes archivable."""
        self.pager.sync(self.record(), [], "mac")
        old = time.time() - 400 * 86400
        marker = self.ws / "stale.txt"
        marker.write_text("x")
        os.utime(marker, (old, old))
        os.utime(self.ws, (old, old))
        self.assertEqual(self.pager.plan()[0]["action"], "LIVENESS_PROBE_REQUIRED")
        with mock.patch.object(wp, "_self_host", return_value="mac"):
            stats = self.pager.refresh_tree_liveness()
        self.assertEqual(stats["probed"], 1)
        self.assertEqual(stats["live"], 0)
        self.assertEqual(self.pager.plan()[0]["action"], "ARCHIVE_CANDIDATE")
        self.assertEqual(self.pager.status()["rows"][0]["tree_recent"], 0)

    def test_liveness_cache_survives_sync(self):
        """sync() is INSERT OR REPLACE; omitted columns silently reset to NULL.

        If the probe cache is wiped on every reconciliation the whole pool falls
        back to LIVENESS_PROBE_REQUIRED and archiving stalls until the next probe.
        """
        self.pager.sync(self.record(), [], "mac")
        self.probed_cold()
        self.pager.sync(self.record(), [], "mac")
        row = self.pager.status()["rows"][0]
        self.assertEqual(row["tree_recent"], 0)
        self.assertIsNotNone(row["tree_probed_at"])
        self.assertEqual(self.pager.plan()[0]["action"], "ARCHIVE_CANDIDATE")

    def test_liveness_cache_survives_asset_sync(self):
        """Same guarantee on the asset-driven upsert path."""
        asset = {
            "asset_id": "keepprobe", "host": "mac", "original_path": str(self.ws),
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 12,
        }
        self.pager.sync(self.record(), [asset], "mac")
        self.probed_cold()
        self.pager.sync(self.record(), [asset], "mac")
        self.assertEqual(self.pager.status()["rows"][0]["tree_recent"], 0)

    def test_sync_touch_pin_state_machine(self):
        got = self.pager.sync(self.record(), [], "mac")
        self.assertEqual(got["added"], 1)
        row = self.pager.touch("mac", str(self.ws), "unit", lease_hours=1)
        self.assertEqual(row["state"], "HOT")
        row = self.pager.set_pin("mac", str(self.ws), True, "unit")
        self.assertEqual(row["state"], "PINNED")
        row = self.pager.set_pin("mac", str(self.ws), False, "unit")
        self.assertEqual(row["state"], "HOT")

    def test_cold_page_cannot_be_pinned_until_restored(self):
        self.pager.sync(self.record(), [], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET state='COLD',local_present=0,pinned=0")
        with self.assertRaisesRegex(wp.PagerRefused, "REFUSE_PIN_REQUIRES_LOCAL_COPY"):
            self.pager.set_pin("mac", str(self.ws), True, "unit")
        row = self.pager.set_pin("mac", str(self.ws), False, "unit")
        self.assertEqual(row["state"], "COLD")
        self.assertEqual(row["pinned"], 0)
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET local_present=1")
        row = self.pager.set_pin("mac", str(self.ws), True, "restored")
        self.assertEqual(row["state"], "PINNED")

    def test_old_unarchived_workspace_is_archive_candidate(self):
        self.pager.sync(self.record(), [], "mac")
        self.probed_cold()
        plan = self.pager.plan(hot_days=3, cold_days=15)
        self.assertEqual(plan[0]["action"], "ARCHIVE_CANDIDATE")

    def test_unprobed_old_workspace_is_not_archive_candidate(self):
        """Without filesystem evidence an ancient-looking page must not be archived."""
        self.pager.sync(self.record(), [], "mac")
        plan = self.pager.plan(hot_days=3, cold_days=15)
        self.assertEqual(plan[0]["action"], "LIVENESS_PROBE_REQUIRED")

    def test_live_tree_is_kept_hot_despite_ancient_last_access(self):
        """A busy tree with a stale HANDOFF must never cool.

        Regression for the hostb pool where agent_roles (70GB, 123356 files
        written in 7d) and .coldstore/dispatch (7.4GB, 10812 files) were both queued
        as ARCHIVE_CANDIDATE purely because their HANDOFF mtime was old.
        """
        self.pager.sync(self.record(), [], "mac")
        with self.pager.connect() as conn:
            conn.execute(
                "UPDATE pages SET tree_recent=1,tree_probed_at=?,tree_probe_days=?",
                (time.time(), self.pager.policy.get("liveness_window_days")
                 or self.pager.policy.get("hot_days", 3)))
        plan = self.pager.plan(hot_days=3, cold_days=15)
        self.assertEqual(plan[0]["action"], "KEEP_HOT")
        self.assertEqual(plan[0]["state"], "HOT")

    def test_cloud_copy_without_snapshot_needs_rearchive_never_restore(self):
        """<date> trust-the-cloud: a cloud copy without an archive-time snapshot
        goes straight to REARCHIVE_REQUIRED; INITIAL_RESTORE_REQUIRED no longer exists
        and a restore mark neither helps nor is asked for."""
        asset = {
            "asset_id": "a", "host": "mac", "original_path": str(self.ws),
            "cloud_verified": True, "restore_verified": False,
            "snapshot_verified": False, "indexed_at_epoch": time.time(), "size_bytes": 12,
        }
        self.pager.sync(self.record(), [asset], "mac")
        row = self.pager.status()["rows"][0]
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE workspace_key=?",
                         (time.time() - 20 * 86400, row["workspace_key"]))
        self.assertEqual(self.pager.plan()[0]["action"], "REARCHIVE_REQUIRED")
        self.pager.mark_restore_verified("a", "unit")
        self.assertEqual(self.pager.plan()[0]["action"], "REARCHIVE_REQUIRED")
        self.assertNotIn("INITIAL_RESTORE_REQUIRED", {r["action"] for r in self.pager.plan()})

    def test_cloud_and_snapshot_proven_page_is_evictable_without_restore_proof(self):
        """The eviction chain never asks for restore_verified (<date>)."""
        path = "/home/user/norestoreproven"
        record = {"hostb|" + path: {"host": "hostb", "path": path, "mtime": time.time() - 20 * 86400}}
        asset = {
            "asset_id": "nr", "host": "hostb", "original_path": path,
            "local_state": "replicated", "cloud_verified": True, "restore_verified": False,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 4096,
            "redundancy_class": "CLOUD_ACCEPTED", "independent_copies": 1,
            "classification_reason": "unit: cloud + archive snapshot", "classified_at_epoch": time.time(),
        }
        self.pager.sync(record, [asset], "mac")
        self.probed_cold()
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE cloud_asset_id='nr'",
                         (time.time() - 20 * 86400,))
        row = next(r for r in self.pager.status()["rows"] if r["cloud_asset_id"] == "nr")
        self.assertEqual(row["restore_verified"], 0)
        self.assertEqual(next(r for r in self.pager.plan() if r["asset_id"] == "nr")["action"],
                         "EVICT_CANDIDATE")
        self.assertEqual([r["asset_id"] for r in self.pager.eviction_candidates()], ["nr"])
        source = Path(wp.__file__).read_text(encoding="utf-8")
        self.assertNotIn("INITIAL_RESTORE_REQUIRED", source)
        self.assertNotIn("AND restore_verified=1", source)  # pressure_waiting no longer gates on it

    def test_verified_asset_requires_classification_and_redundancy(self):
        asset = {
            "asset_id": "classified", "host": "mac", "original_path": str(self.ws),
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 12,
        }
        self.pager.sync(self.record(), [asset], "mac")
        row = self.pager.status()["rows"][0]
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE workspace_key=?",
                         (time.time() - 20 * 86400, row["workspace_key"]))
        self.probed_cold()
        self.assertEqual(self.pager.plan()[0]["action"], "CLASSIFY_REQUIRED")
        self.pager.set_classification("mac", str(self.ws), "VALUABLE", 1, "unit")
        self.assertEqual(self.pager.plan()[0]["action"], "RETAIN_REDUNDANCY_REQUIRED")
        self.pager.set_classification("mac", str(self.ws), "VALUABLE", 2, "unit")
        self.assertEqual(self.pager.plan()[0]["action"], "EVICT_CANDIDATE")
        self.pager.sync(self.record(), [asset], "mac")
        row = self.pager.status()["rows"][0]
        self.assertEqual((row["redundancy_class"], row["independent_copies"]),
                         ("VALUABLE", 2))

    def test_fully_proven_cloud_catalog_asset_gets_cold_contract_classification(self):
        catalog = self.root / "catalog.jsonl"
        restored = self.root / "restore.tsv"
        catalog.write_text("\n".join(json.dumps(row) for row in [
            {
                "asset_id": "proven", "machine": "hostb",
                "original_path": "/home/user/proven", "size": 12,
                "cloud_state": "confirmed", "snapshot_verified": True,
                "archived_at": "<date>T00:00:00+00:00",
            },
            {
                "asset_id": "no-snapshot", "machine": "hostb",
                "original_path": "/home/user/no-snapshot", "size": 12,
                "cloud_state": "confirmed", "snapshot_verified": False,
                "archived_at": "<date>T00:00:00+00:00",
            },
        ]) + "\n", encoding="utf-8")
        restored.write_text(
            "proven\tnow\tfixture\tPASS\tok\n"
            "no-snapshot\tnow\tfixture\tPASS\tok\n",
            encoding="utf-8",
        )
        assets = {row["asset_id"]: row for row in wp.load_assets(catalog, restored)}
        self.assertEqual(
            (assets["proven"]["redundancy_class"],
             assets["proven"]["independent_copies"]),
            ("CLOUD_ACCEPTED", 1),
        )
        self.assertEqual(assets["no-snapshot"]["redundancy_class"], "UNCLASSIFIED")

    def test_load_assets_v3_rows_self_assert_restore_only_when_tagged(self):
        catalog = self.root / "catalog_v3.jsonl"
        restored = self.root / "restored_v3.tsv"
        catalog.write_text("\n".join(json.dumps(row) for row in [
            {
                "asset_id": "hostb-asset-pool-v3-batch-0002", "machine": "hostb",
                "original_path": "/home/user/asset-pool-v3/batch-0002", "size": 12,
                "cloud_state": "confirmed", "snapshot_verified": True,
                "archived_at": "<date>T22:59:05-07:00",
                "vault": "v3", "restore_verified": True,
            },
            {
                "asset_id": "untagged-claims-restore", "machine": "hostb",
                "original_path": "/home/user/untagged", "size": 12,
                "cloud_state": "confirmed", "snapshot_verified": True,
                "archived_at": "<date>T22:59:05-07:00",
                "restore_verified": True,
            },
        ]) + "\n", encoding="utf-8")
        restored.write_text("", encoding="utf-8")
        assets = {row["asset_id"]: row for row in wp.load_assets(catalog, restored)}
        v3 = assets["hostb-asset-pool-v3-batch-0002"]
        self.assertTrue(v3["restore_verified"])
        self.assertEqual((v3["redundancy_class"], v3["independent_copies"]), ("CLOUD_ACCEPTED", 1))
        self.assertFalse(assets["untagged-claims-restore"]["restore_verified"])
        # <date>: cloud + snapshot is the whole proof; restore_verified is informational
        self.assertEqual(assets["untagged-claims-restore"]["redundancy_class"], "CLOUD_ACCEPTED")

    def test_catalog_classification_imports_but_never_overrides_manual_class(self):
        asset = {
            "asset_id": "proven", "host": "mac", "original_path": str(self.ws),
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(),
            "size_bytes": 12, "redundancy_class": "CLOUD_ACCEPTED",
            "independent_copies": 1,
            "classification_reason": "user-approved cold contract",
        }
        self.pager.sync(self.record(), [asset], "mac")
        row = self.pager.status()["rows"][0]
        self.assertEqual(
            (row["redundancy_class"], row["independent_copies"]),
            ("CLOUD_ACCEPTED", 1),
        )
        self.pager.set_classification("mac", str(self.ws), "VALUABLE", 2, "unit")
        self.pager.sync(self.record(), [asset], "mac")
        row = self.pager.status()["rows"][0]
        self.assertEqual(
            (row["redundancy_class"], row["independent_copies"]),
            ("VALUABLE", 2),
        )

    def test_eviction_cannot_enable_before_pool_migration_complete(self):
        policy = json.loads(wp.DEFAULT_POLICY.read_text(encoding="utf-8"))
        policy["evict_enabled"] = True
        policy["pool_migration_state"] = "DRAINING"
        path = self.root / "policy.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(
                wp.PagerRefused, "EVICTION_BEFORE_MIGRATION_COMPLETE"):
            wp.load_policy(path)
        policy["pool_migration_state"] = "COMPLETE"
        path.write_text(json.dumps(policy), encoding="utf-8")
        self.assertTrue(wp.load_policy(path)["evict_enabled"])

    def test_explicit_asset_reference_becomes_prefetch_requirement(self):
        asset = {
            "asset_id": "tool-abc", "host": "mac", "original_path": str(self.root / "gone"),
            "cloud_verified": True,
        }
        got = self.pager.requirements_from_text("use tool-abc", [asset])
        self.assertEqual(got[0]["needs_restore"], True)

    def test_asset_and_path_prefixes_do_not_become_requirements(self):
        asset = {"asset_id": "asset", "host": "hostb",
                 "original_path": "/data/video", "cloud_verified": True}
        got = self.pager.requirements_from_text(
            "use asset-new at /data/video_full/output", [asset])
        self.assertEqual(got, [])

    def test_asset_without_workspace_is_first_class_page(self):
        path = self.root / "cloud_only.bin"
        asset = {
            "asset_id": "file-only", "host": "mac", "original_path": str(path),
            "cloud_verified": True, "restore_verified": False,
            "snapshot_verified": True, "local_state": "cloud_only",
            "indexed_at_epoch": time.time() - 86400, "size_bytes": 123,
        }
        got = self.pager.sync({}, [asset], "mac")
        self.assertEqual((got["added"], got["mapped"]), (1, 1))
        row = self.pager.status("file-only")["rows"][0]
        self.assertEqual((row["state"], row["local_present"]), ("COLD", 0))
        path.write_bytes(b"restored")
        self.assertEqual(self.pager.mark_restore_verified("file-only", "unit"), 1)
        self.assertEqual(self.pager.mark_materialized("file-only", "unit"), 1)
        row = self.pager.status("file-only")["rows"][0]
        self.assertEqual((row["state"], row["local_present"], row["restore_verified"]),
                         ("HOT", 1, 1))

    def test_remote_catalog_local_state_is_authoritative_for_presence(self):
        path = "/home/user/remote-asset"
        asset = {
            "asset_id": "remote", "host": "hostb", "original_path": path,
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "local_state": "replicated",
            "indexed_at_epoch": time.time(), "size_bytes": 321,
        }
        self.pager.sync({}, [asset], "mac")
        self.assertEqual(self.pager.status("remote")["rows"][0]["local_present"], 1)
        asset["local_state"] = "cloud_only"
        self.pager.sync({}, [asset], "mac")
        self.assertEqual(self.pager.status("remote")["rows"][0]["local_present"], 0)

    def test_new_snapshot_clears_standalone_dirty_but_old_snapshot_does_not(self):
        path = "/home/user/standalone"
        archived = time.time() - 100
        asset = {
            "asset_id": "standalone", "host": "hostb", "original_path": path,
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "local_state": "replicated",
            "indexed_at_epoch": archived, "size_bytes": 321,
        }
        self.pager.sync({}, [asset], "mac")
        self.pager.mark_dirty("hostb", path, "write after archive")
        self.pager.sync({}, [asset], "mac")
        self.assertEqual(self.pager.status(path)["rows"][0]["dirty"], 1)
        asset["indexed_at_epoch"] = time.time() + 1
        self.pager.sync({}, [asset], "mac")
        self.assertEqual(self.pager.status(path)["rows"][0]["dirty"], 0)

    def test_workspace_sync_preserves_dirty_write_until_new_confirmed_snapshot(self):
        path = "/home/user/changed-workspace"
        archived = time.time() - 200
        record = {path: {"host": "hostb", "path": path, "mtime": archived - 100}}
        asset = {"asset_id": "changed-workspace", "host": "hostb", "original_path": path,
                 "cloud_verified": True, "snapshot_verified": True,
                 "local_state": "replicated", "indexed_at_epoch": archived, "size_bytes": 321}
        self.pager.sync(record, [asset], "mac")
        self.pager.mark_dirty("hostb", path, "executor observed changed content")
        written = self.pager.status(path)["rows"][0]["last_write"]
        self.pager.sync(record, [asset], "mac")
        row = self.pager.status(path)["rows"][0]
        self.assertEqual(row["dirty"], 1)
        self.assertEqual(row["last_write"], written)
        # A newer timestamp alone does not prove an uploaded snapshot.
        asset.update(indexed_at_epoch=written + 1, snapshot_verified=False)
        self.pager.sync(record, [asset], "mac")
        self.assertEqual(self.pager.status(path)["rows"][0]["dirty"], 1)
        asset.update(snapshot_verified=True, cloud_verified=False)
        self.pager.sync(record, [asset], "mac")
        self.assertEqual(self.pager.status(path)["rows"][0]["dirty"], 1)
        asset["cloud_verified"] = True
        self.pager.sync(record, [asset], "mac")
        self.assertEqual(self.pager.status(path)["rows"][0]["dirty"], 0)
        self.assertEqual(self.pager.status(path)["rows"][0]["last_write"], written)

    def test_newer_asset_semantics_replace_existing_page_values(self):
        path = "/home/user/semantic"
        asset = {
            "asset_id": "semantic", "host": "hostb", "original_path": path,
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "local_state": "replicated",
            "indexed_at_epoch": time.time(), "size_bytes": 1,
            "semantic_revision": 1, "content_fingerprint": "a" * 64,
            "annotation_status": "CURRENT", "semantic_summary": "old",
            "semantic_keywords_json": "[]", "annotated_at": 10,
        }
        self.pager.sync({}, [asset], "mac")
        asset.update({
            "semantic_revision": 2, "content_fingerprint": "b" * 64,
            "semantic_summary": "new", "annotated_at": 20,
        })
        self.pager.sync({}, [asset], "mac")
        row = self.pager.status(path)["rows"][0]
        self.assertEqual((row["semantic_revision"], row["content_fingerprint"],
                          row["semantic_summary"]), (2, "b" * 64, "new"))

    def test_asset_relocation_changes_logical_path_without_duplicate_page(self):
        source = "/data/legacy/model"
        target = "/home/user/model"
        asset = {
            "asset_id": "model", "host": "hostb", "original_path": source,
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "local_state": "replicated",
            "indexed_at_epoch": time.time(), "size_bytes": 100,
        }
        self.pager.sync({}, [asset], "mac")
        row = self.pager.relocate_asset(
            "model", "hostb", target, "pool migration", local_present=0)
        self.assertEqual((row["path"], row["storage_pool"], row["state"]),
                         (target, "MANAGED", "COLD"))
        self.assertEqual(len(self.pager.status("model")["rows"]), 1)

    def test_relocation_coalesces_only_explicitly_verified_absent_stale_path(self):
        source = "/data/legacy/model"
        target = "/home/user/model"
        asset = {
            "asset_id": "model", "host": "hostb", "original_path": source,
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "local_state": "replicated",
            "indexed_at_epoch": time.time(), "size_bytes": 100,
        }
        self.pager.sync({}, [asset], "mac")
        moved = dict(asset, original_path=target, local_state="cloud_only")
        self.pager.sync({}, [moved], "mac")
        with self.assertRaisesRegex(wp.PagerRefused, "REFUSE_RELOCATE_ASSET_ROW_COUNT"):
            self.pager.relocate_asset("model", "hostb", target, "unit", local_present=0)
        row = self.pager.relocate_asset(
            "model", "hostb", target, "unit", local_present=0,
            verified_absent_paths=[source],
            verified_snapshot=True,
        )
        self.assertEqual(
            (row["path"], row["state"], row["dirty"], row["snapshot_verified"]),
            (target, "COLD", 0, 1),
        )
        self.assertEqual(len(self.pager.status("model")["rows"]), 1)

    def test_asset_fts_is_created_only_by_explicit_sync_and_repairs_cardinality(self):
        with self.pager.connect() as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='asset_files_fts'"
            ).fetchone())
        self.assertEqual(self.pager.search_asset_files(["android", "crash"]), [])
        with self.pager.connect() as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='asset_files_fts'"
            ).fetchone())

        source = self.manifests / "fixture.jsonl.gz"
        with gzip.open(source, "wt", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "asset_id": "logs", "relative_path": "mobile/android_crash_2026.log",
                "size": 12, "mtime_ns": 123,
            }) + "\n")
            handle.write(json.dumps({
                "asset_id": "qbank", "relative_path": "physics/question_bank.jsonl",
                "size": 34, "mtime_ns": 456,
            }) + "\n")
        result = self.pager.sync({}, [], "mac")
        self.assertEqual((result["asset_files"], result["fts_files"]), (2, 2))
        hit = self.pager.search_asset_files(["android", "crash"])
        self.assertEqual((hit[0]["asset_id"], hit[0]["search_backend"]), ("logs", "fts5"))
        short = self.pager.search_asset_files(["题库"])
        self.assertEqual(short, [])

        with self.pager.connect() as conn:
            conn.execute("DELETE FROM asset_files_fts")
        repaired = self.pager.sync({}, [], "mac")
        self.assertEqual(repaired["fts_rebuilt_files"], 2)
        with self.pager.connect() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM asset_files_fts"
            ).fetchone()[0], 2)

    def test_isolation_mount_never_enters_temperature_or_eviction(self):
        path = "/data/local-llm"
        self.pager.sync({"hostb|" + path: {
            "host": "hostb", "path": path, "mtime": time.time() - 90 * 86400,
        }}, [], "mac")
        row = self.pager.status(path)["rows"][0]
        self.assertEqual((row["storage_pool"], row["state"]), ("ISOLATED", "ISOLATED"))
        item = next(x for x in self.pager.plan() if x["path"] == path)
        self.assertEqual(item["action"], "KEEP_ISOLATED")

    def test_legacy_data_path_returns_to_isolation_after_migration(self):
        path = "/data/asset-pool-v3/batch-0001"
        self.pager.sync({"hostb|" + path: {
            "host": "hostb", "path": path, "mtime": time.time() - 90 * 86400,
        }}, [], "mac")
        row = self.pager.status(path)["rows"][0]
        self.assertEqual((row["storage_pool"], row["state"]),
                         ("ISOLATED", "ISOLATED"))
        self.assertEqual(wp.load_policy()["isolation_exceptions"], [])

    def test_pressure_hysteresis_triggers_at_ten_and_stops_at_fifteen(self):
        low = {"managed": {"total": 1000, "used": 910, "free": 90},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        middle = {"managed": {"total": 1000, "used": 880, "free": 120},
                  "isolated": {"total": 500, "used": 100, "free": 400}}
        stop = {"managed": {"total": 1000, "used": 850, "free": 150},
                "isolated": {"total": 500, "used": 100, "free": 400}}
        first = self.pager.pool_status(low)
        self.assertTrue(first["managed"]["eviction_active"])
        self.assertEqual((first["managed"]["hot_target_bytes"],
                          first["managed"]["warm_target_bytes"]), (630, 270))
        self.assertTrue(self.pager.pool_status(middle)["managed"]["eviction_active"])
        self.assertFalse(self.pager.pool_status(stop)["managed"]["eviction_active"])

    def test_capacity_demand_wakes_twelve_percent_and_stops_at_real_target(self):
        disk = {'managed': {'total': 1000, 'used': 880, 'free': 120},
                'isolated': {'total': 500, 'used': 100, 'free': 400}}
        self.assertFalse(self.pager.pool_status(disk)['managed']['eviction_active'])
        self.pager.request_capacity('asset-pool-v3', 230, batch_id='batch-0003',
                                    manifest_sha256='a' * 64)
        status = self.pager.pool_status(disk)['managed']
        self.assertTrue(status['eviction_active'])
        self.assertFalse(status['watermark_eviction_active'])
        self.assertEqual(status['bytes_to_stop'], 110)
        disk['managed'].update(free=151, used=849)
        self.assertTrue(self.pager.pool_status(disk)['managed']['eviction_active'])
        disk['managed'].update(free=230, used=770)
        self.assertFalse(self.pager.pool_status(disk)['managed']['eviction_active'])

    def test_capacity_expiry_and_release_do_not_latch_watermark(self):
        disk = {'managed': {'total': 1000, 'used': 880, 'free': 120},
                'isolated': {'total': 500, 'used': 100, 'free': 400}}
        with mock.patch.object(wp.time, 'time', return_value=100):
            self.pager.request_capacity('asset-pool-v3', 230, batch_id='batch-0003',
                                        manifest_sha256='a'*64, ttl=60)
        with mock.patch.object(wp.time, 'time', return_value=161):
            self.assertFalse(self.pager.pool_status(disk)['managed']['eviction_active'])
        self.pager.request_capacity('asset-pool-v3', 230, batch_id='batch-0004',
                                    manifest_sha256='b'*64)
        self.pager.release_capacity('asset-pool-v3', batch_id='batch-0003')
        self.assertTrue(self.pager.pool_status(disk)['managed']['eviction_active'])
        self.pager.release_capacity('asset-pool-v3', batch_id='batch-0004')
        self.assertFalse(self.pager.pool_status(disk)['managed']['eviction_active'])

    def test_capacity_request_is_narrow_and_does_not_make_pages_eligible(self):
        for owner, target, ttl in [('other', 300, 3600), ('asset-pool-v3', -1, 3600),
                                    ('asset-pool-v3', 300, 999999)]:
            with self.assertRaises(wp.PagerRefused):
                self.pager.request_capacity(owner, target, batch_id='batch-0003',
                                            manifest_sha256='a'*64, ttl=ttl)
        before = self.pager.status()['rows']
        self.pager.request_capacity('asset-pool-v3', 230, batch_id='batch-0003',
                                    manifest_sha256='a'*64)
        self.assertEqual(before, self.pager.status()['rows'])

    def test_semantic_write_requires_real_content_annotation(self):
        changed = self.ws / "content.txt"
        changed.write_text("version one", encoding="utf-8")
        self.pager.sync(self.record(), [], "mac")
        stale = self.pager.mark_semantic_stale(
            "mac", str(self.ws), [str(changed)], "unit", "task-1")
        self.assertEqual(stale["annotation_status"], "SEMANTIC_STALE")
        with self.assertRaisesRegex(wp.PagerRefused, "TASK_MISMATCH"):
            self.pager.annotate("mac", str(self.ws), "摘要", ["词"], "unit", "task-2")
        row = self.pager.annotate(
            "mac", str(self.ws), "真实新内容", ["内容", "测试"], "unit", "task-1")
        self.assertEqual((row["annotation_status"], row["semantic_revision"]), ("CURRENT", 1))
        self.assertEqual(len(row["content_fingerprint"]), 64)
        with self.pager.connect() as conn:
            hit = conn.execute(
                "SELECT count(*) FROM page_semantics_fts WHERE page_semantics_fts MATCH '真实新'"
            ).fetchone()[0]
        self.assertEqual(hit, 1)

    def test_semantic_export_merge_is_monotonic_and_idempotent(self):
        authority = self.root / "authority.jsonl"
        incoming = self.root / "incoming.jsonl"

        def row(host, path, revision, fingerprint, summary):
            return {
                "host": host, "path": path,
                "workspace_key": wp.WorkspacePager.key(host, path),
                "cloud_asset_id": None, "summary": summary,
                "keywords_json": json.dumps(["unit"], ensure_ascii=False),
                "semantic_revision": revision, "content_fingerprint": fingerprint,
                "annotated_by": "unit", "annotated_at": 10.0,
                "index_synced_at": 11.0,
            }

        old = row("mac", "/tmp/a", 2, "a" * 64, "newer")
        stale = row("mac", "/tmp/a", 1, "b" * 64, "stale")
        added = row("hostb", "/tmp/b", 1, "c" * 64, "added")
        authority.write_text(json.dumps(old) + "\n", encoding="utf-8")
        incoming.write_text(json.dumps(stale) + "\n" + json.dumps(added) + "\n",
                            encoding="utf-8")
        result = wp.merge_semantic_exports(authority, incoming)
        self.assertEqual((result["rows"], result["inserted"], result["stale"]), (2, 1, 1))
        merged = wp._load_semantic_rows(authority)
        self.assertEqual(merged["mac|/tmp/a"]["summary"], "newer")
        result = wp.merge_semantic_exports(authority, incoming)
        self.assertEqual((result["rows"], result["stale"], result["identical"]), (2, 1, 1))

    def test_semantic_export_equal_revision_conflict_fails_closed(self):
        authority = self.root / "authority.jsonl"
        incoming = self.root / "incoming.jsonl"
        base = {
            "host": "mac", "path": "/tmp/a", "workspace_key": "mac|/tmp/a",
            "cloud_asset_id": None, "summary": "one", "keywords_json": "[]",
            "semantic_revision": 1, "content_fingerprint": "a" * 64,
            "annotated_by": "unit", "annotated_at": 10.0, "index_synced_at": 11.0,
        }
        authority.write_text(json.dumps(base) + "\n", encoding="utf-8")
        conflict = dict(base, summary="two")
        incoming.write_text(json.dumps(conflict) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(wp.PagerRefused, "REVISION_CONFLICT"):
            wp.merge_semantic_exports(authority, incoming)
        self.assertEqual(wp._load_semantic_rows(authority)["mac|/tmp/a"]["summary"], "one")

    def test_sync_failed_annotation_recovers_without_revision_churn(self):
        changed = self.ws / "content.txt"
        changed.write_text("version one", encoding="utf-8")
        self.pager.sync(self.record(), [], "mac")
        self.pager.mark_semantic_stale(
            "mac", str(self.ws), [str(changed)], "unit", "task-1")
        annotated = self.pager.annotate(
            "mac", str(self.ws), "真实新内容", ["内容"], "unit", "task-1")
        self.pager.mark_annotation_sync_failed("mac", str(self.ws), "unit failure")
        recovered = self.pager.mark_annotation_sync_complete("mac", str(self.ws))
        self.assertEqual(recovered["annotation_status"], "CURRENT")
        self.assertEqual(recovered["semantic_revision"], annotated["semantic_revision"])
        self.assertEqual(recovered["content_fingerprint"], annotated["content_fingerprint"])
        with self.assertRaisesRegex(wp.PagerRefused, "NOT_SYNC_FAILED"):
            self.pager.mark_annotation_sync_complete("mac", str(self.ws))

    def test_semantic_stale_page_cannot_become_evict_candidate(self):
        asset = {
            "asset_id": "semantic", "host": "mac", "original_path": str(self.ws),
            "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 12,
        }
        self.pager.sync(self.record(), [asset], "mac")
        self.pager.set_classification("mac", str(self.ws), "CLOUD_ACCEPTED", 1, "unit")
        changed = self.ws / "x"; changed.write_text("x")
        self.pager.mark_semantic_stale("mac", str(self.ws), [str(changed)], "unit", "task")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE workspace_key=?",
                         (time.time() - 20 * 86400, "mac|" + str(self.ws)))
        self.assertEqual(self.pager.plan()[0]["action"], "SEMANTIC_PATCH_REQUIRED")

    def test_legacy_state_check_is_migrated_without_row_loss(self):
        old_db = self.root / "legacy.db"
        with sqlite3.connect(old_db) as conn:
            conn.execute("""CREATE TABLE pages(
                workspace_key TEXT PRIMARY KEY,host TEXT NOT NULL,path TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('HOT','WARM','COLD','PINNED')),
                pinned INTEGER NOT NULL DEFAULT 0,local_present INTEGER NOT NULL DEFAULT -1,
                dirty INTEGER NOT NULL DEFAULT 1,updated_at REAL NOT NULL)""")
            conn.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?,?)",
                         ("hostb|/data/local-llm", "hostb", "/data/local-llm", "HOT", 0, 1, 1, time.time()))
        migrated = wp.WorkspacePager(old_db, manifest_dir=self.manifests)
        rows = migrated.status()["rows"]
        self.assertEqual(len(rows), 1)
        with migrated.connect() as conn:
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='pages'"
            ).fetchone()[0]
        self.assertIn("'ISOLATED'", sql)

    def test_alert_contract_has_only_actionable_pool_and_semantic_states(self):
        disk = {"managed": {"total": 1000, "used": 800, "free": 200},
                "isolated": {"total": 500, "used": 460, "free": 40}}
        codes = {x["code"] for x in self.pager.alerts(disk_stats=disk)}
        self.assertIn("PAGER_ISOLATION_LOW", codes)
        self.assertNotIn("PAGER_EVICTING", codes)

        low = {"managed": {"total": 1000, "used": 920, "free": 80},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        codes = {x["code"] for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_PRESSURE_STUCK", codes)

    def _isolation_alert(self, free: int, total: int = 1000):
        """Only the isolated pool varies; managed stays comfortably above water."""
        disk = {"managed": {"total": 1000, "used": 100, "free": 900},
                "isolated": {"total": total, "used": total - free, "free": free}}
        for alert in self.pager.alerts(disk_stats=disk):
            if alert["code"] == "PAGER_ISOLATION_LOW":
                return alert
        return None

    def test_isolation_low_escalates_to_err_when_pool_is_nearly_full(self):
        """PAGER_ISOLATION_LOW must have an err form.

        Widget acks are level-scoped: `_ack_covers` keeps a user's "not important"
        silence only while the alert stays at the acked level.  A code with a
        single warn level can therefore be silenced all the way down to a full
        disk.  roles_watchdog also skips the generic hostb.disk_data DISK_HIGH
        check whenever this code is present, so err is the pool's only remaining
        route to the screen.
        """
        shipped = wp.load_policy()
        warn_line = float(shipped["isolation_warn_free_ratio"])
        err_line = float(shipped.get("isolation_err_free_ratio",
                                     wp.DEFAULT_ISOLATION_ERR_FREE_RATIO))
        self.assertLess(err_line, warn_line, "err line must sit below the warn line")

        above = self._isolation_alert(int(1000 * warn_line) + 50)
        self.assertIsNone(above, "no alert while the pool is above the warn line")

        warned = self._isolation_alert(int(1000 * (warn_line + err_line) / 2))
        self.assertIsNotNone(warned)
        self.assertEqual(warned["level"], "warn")

        critical = self._isolation_alert(max(1, int(1000 * err_line) - 5))
        self.assertIsNotNone(critical)
        self.assertEqual(critical["level"], "err",
                         "a nearly-full isolation pool must outrank a warn-level ack")
        # The thresholds travel with the alert so the reader can tell which line
        # was crossed without opening the policy file.
        self.assertIn("err_below=", critical["detail"])

    def test_isolation_thresholds_must_be_ordered(self):
        policy = json.loads(wp.DEFAULT_POLICY.read_text(encoding="utf-8"))
        path = self.root / "iso_policy.json"
        policy["isolation_err_free_ratio"] = policy["isolation_warn_free_ratio"]
        path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(wp.PagerRefused,
                                    "ISOLATION_THRESHOLD_ORDER"):
            wp.load_policy(path)
        policy["isolation_err_free_ratio"] = 0.0
        path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(wp.PagerRefused,
                                    "ISOLATION_THRESHOLD_ORDER"):
            wp.load_policy(path)
        # Absent key is legal: shipped policies predate it and must still load.
        policy.pop("isolation_err_free_ratio")
        path.write_text(json.dumps(policy), encoding="utf-8")
        self.assertEqual(float(wp.load_policy(path)["isolation_err_free_ratio"]),
                         wp.DEFAULT_ISOLATION_ERR_FREE_RATIO)

    def test_pressure_with_proven_page_in_hot_grace_is_waiting_not_stuck(self):
        path = "/home/user/hotproven"
        record = {"hostb|" + path: {"host": "hostb", "path": path, "mtime": time.time() - 86400}}
        asset = {
            "asset_id": "hot-proven", "host": "hostb", "original_path": path,
            "local_state": "replicated", "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 4096,
            "redundancy_class": "CLOUD_ACCEPTED", "independent_copies": 1,
            "classification_reason": "unit: proven v3 batch", "classified_at_epoch": time.time(),
        }
        self.pager.sync(record, [asset], "mac")
        self.probed_cold()
        low = {"managed": {"total": 1000, "used": 920, "free": 80},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        alerts = {x["code"]: x for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_PRESSURE_WAITING", alerts)
        self.assertNotIn("PAGER_PRESSURE_STUCK", alerts)
        self.assertEqual(alerts["PAGER_PRESSURE_WAITING"]["level"], "warn")
        waiting = self.pager.pressure_waiting()
        self.assertEqual([w["asset_id"] for w in waiting], ["hot-proven"])
        self.assertEqual(waiting[0]["reason"], "hot_grace")
        # once the grace window has elapsed the same page is a real candidate
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=? WHERE cloud_asset_id='hot-proven'",
                         (time.time() - 20 * 86400,))
        self.assertEqual(self.pager.pressure_waiting(), [])
        codes = {x["code"] for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_EVICTING", codes)
        self.assertNotIn("PAGER_PRESSURE_STUCK", codes)

    def test_proven_page_past_hot_grace_but_before_cold_is_pressure_candidate(self):
        """<date>: pressure candidacy floors at hot_days, matching pressure_waiting()."""
        path = "/home/user/midproven"
        record = {"hostb|" + path: {"host": "hostb", "path": path, "mtime": time.time() - 86400}}
        asset = {
            "asset_id": "mid-proven", "host": "hostb", "original_path": path,
            "local_state": "replicated", "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 4096,
            "redundancy_class": "CLOUD_ACCEPTED", "independent_copies": 1,
            "classification_reason": "unit: proven v3 batch", "classified_at_epoch": time.time(),
        }
        self.pager.sync(record, [asset], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE cloud_asset_id='mid-proven'",
                         (time.time() - 5 * 86400,))
        self.probed_cold()
        # calm-state schedule unchanged: 5 days old is still only cooling
        self.assertEqual(self.pager.plan(3, 15)[0]["action"], "COOL_TO_WARM")
        # but under pressure it is a real candidate, not invisible
        self.assertEqual([c["asset_id"] for c in self.pager.eviction_candidates()], ["mid-proven"])
        self.assertEqual(self.pager.pressure_waiting(), [])
        low = {"managed": {"total": 1000, "used": 920, "free": 80},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        codes = {x["code"] for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_EVICTING", codes)
        self.assertNotIn("PAGER_PRESSURE_STUCK", codes)

    def test_shipped_policy_retires_the_cool_to_warm_limbo(self):
        """WARM must mean "the archive pipeline owns this page", never a dead wait.

        The retired 15-day schedule parked pages aged hot_days..15 in COOL_TO_WARM:
        state=WARM (so they counted as warm capacity) but no action, so they were never
        uploaded and could never become evictable -- 206 pages / 82.9GB deadlocked the
        pool.  The institution is water-level driven; a page is warm the moment it stops
        being hot, and warm means local *and* cloud co-held.
        """
        shipped = wp.load_policy()
        self.assertLessEqual(float(shipped["cold_days"]), float(shipped["hot_days"]),
                             "cold_days above hot_days re-opens the COOL_TO_WARM limbo")
        # The filesystem probe must answer to the same hot/warm boundary, not to the
        # retired schedule; otherwise one tree is hot or warm depending on which clock.
        self.assertEqual(float(shipped.get("liveness_window_days")),
                         float(shipped["hot_days"]))
        # Defaults must come from policy, not from a literal in the signature.
        self.pager.sync(self.record(), [], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?", (time.time() - 5 * 86400,))
        self.probed_cold()
        self.assertNotIn("COOL_TO_WARM", {row["action"] for row in self.pager.plan()})

    def test_locally_absent_uncloudy_page_is_an_orphan_not_a_probe_request(self):
        """A deleted tree that never reached the cloud must not demand a local probe.

        refresh_tree_liveness() skips local_present=0 rows -- there is nothing to stat --
        but plan() used to route them into the archive chain, which fails closed on
        missing filesystem evidence.  188 deleted agent-b research dirs were therefore
        pinned at LIVENESS_PROBE_REQUIRED forever, a demand no probe could ever satisfy.
        """
        self.pager.sync(self.record(), [], "mac")
        with self.pager.connect() as conn:
            conn.execute(
                "UPDATE pages SET local_present=0,cloud_verified=0,tree_recent=NULL,"
                "tree_probed_at=NULL,last_access=?", (time.time() - 40 * 86400,))
        row = self.pager.plan()[0]
        self.assertEqual(row["action"], "RECORD_ORPHANED")
        # Never probed, and the probe must keep ignoring it (nothing local to stat).
        probe = self.pager.refresh_tree_liveness()
        self.assertEqual(probe["considered"], 0)
        # Orphans must stay out of every pipeline: archive, restore and eviction.
        self.assertEqual(self.pager.eviction_candidates(), [])

    def test_executor_block_removes_candidate_and_is_reported_in_stuck(self):
        path = "/home/user/blockedproven"
        record = {"hostb|" + path: {"host": "hostb", "path": path, "mtime": time.time() - 86400}}
        asset = {
            "asset_id": "blocked-proven", "host": "hostb", "original_path": path,
            "local_state": "replicated", "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 4096,
            "redundancy_class": "CLOUD_ACCEPTED", "independent_copies": 1,
            "classification_reason": "unit: proven v3 batch", "classified_at_epoch": time.time(),
        }
        self.pager.sync(record, [asset], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL WHERE cloud_asset_id='blocked-proven'",
                         (time.time() - 20 * 86400,))
        self.probed_cold()
        self.assertEqual([c["asset_id"] for c in self.pager.eviction_candidates()], ["blocked-proven"])
        self.pager.block_eviction("blocked-proven", "REFUSE_SOURCE_PATH_TOO_BROAD")
        self.assertEqual(self.pager.eviction_candidates(), [])
        self.assertIn("blocked-proven", self.pager.eviction_blocks())
        low = {"managed": {"total": 1000, "used": 920, "free": 80},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        alerts = {x["code"]: x for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_PRESSURE_STUCK", alerts)
        self.assertIn("blocked=1", alerts["PAGER_PRESSURE_STUCK"]["detail"])
        self.assertIn("REFUSE_SOURCE_PATH_TOO_BROAD", alerts["PAGER_PRESSURE_STUCK"]["detail"])
        self.assertTrue(self.pager.unblock_eviction("blocked-proven"))
        self.assertFalse(self.pager.unblock_eviction("blocked-proven"))
        self.assertEqual([c["asset_id"] for c in self.pager.eviction_candidates()], ["blocked-proven"])

    def test_unblock_eviction_preserves_newer_refusal(self):
        self.pager.block_eviction("synthetic", "NO_ELIGIBLE_CONFIRMED_hostb_ASSET")
        before = self.pager.eviction_blocks()["synthetic"]
        self.pager.block_eviction("synthetic", "REFUSE_LOCAL_CHANGED_REARCHIVE_REQUIRED")
        self.assertFalse(self.pager.unblock_eviction("synthetic", expected=before))
        current = self.pager.eviction_blocks()["synthetic"]
        self.assertIn("REFUSE_LOCAL_CHANGED", current["reason"])
        self.assertTrue(self.pager.unblock_eviction("synthetic", expected=current))
        self.assertNotIn("synthetic", self.pager.eviction_blocks())

    def _proven_evictable(self, asset_id, path):
        """A page with every deletion proof in place, cold enough to be a candidate."""
        record = {"hostb|" + path: {"host": "hostb", "path": path,
                                   "mtime": time.time() - 86400}}
        asset = {
            "asset_id": asset_id, "host": "hostb", "original_path": path,
            "local_state": "replicated", "cloud_verified": True, "restore_verified": True,
            "snapshot_verified": True, "indexed_at_epoch": time.time(), "size_bytes": 4096,
            "redundancy_class": "CLOUD_ACCEPTED", "independent_copies": 1,
            "classification_reason": "unit: proven", "classified_at_epoch": time.time(),
        }
        self.pager.sync(record, [asset], "mac")
        with self.pager.connect() as conn:
            conn.execute("UPDATE pages SET last_access=?,lease_until=NULL "
                         "WHERE cloud_asset_id=?", (time.time() - 20 * 86400, asset_id))
        self.probed_cold()

    def test_transient_eviction_refusal_returns_to_pool_after_retry_window(self):
        """A transient refusal must age out by itself, not wait for a human.

        <date>: this ledger was a *permanent* blacklist while its archive twin always
        expired entries, so one blip (REFUSE_SOURCE_HAS_OPEN_HANDLES: somebody held the
        file open for a second) removed an asset from the pool forever.  The pool could
        only shrink and the evictor starved by construction -- 383 entries hand-cleared
        on <date> had regrown to 192 by <date>, every one of them without an expiry, while
        free space fell back to 6.10%.  Expiry is a *re-judgement*, not a waiver.

        This asserts through ``eviction_candidates`` on purpose: asserting only on
        ``eviction_blocks`` would still pass if the candidate query kept calling the
        unbounded ledger, which is exactly the half-fix to agent-b against.
        """
        self._proven_evictable("transient-proven", "/home/user/transientblock")
        self.assertEqual([c["asset_id"] for c in self.pager.eviction_candidates()],
                         ["transient-proven"])
        self.pager.block_eviction("transient-proven",
                                  "REFUSE_SOURCE_HAS_OPEN_HANDLES", retry_after_sec=600)
        self.assertEqual(self.pager.eviction_candidates(), [])
        with mock.patch.object(wp.time, "time", return_value=time.time() + 601):
            self.assertEqual([c["asset_id"] for c in self.pager.eviction_candidates()],
                             ["transient-proven"])
            self.assertNotIn("transient-proven", self.pager.eviction_blocks(7))
            # The refusal itself is never forgotten -- the raw ledger is the evidence.
            self.assertIn("transient-proven", self.pager.eviction_blocks())

    def test_eviction_block_without_retry_still_expires_by_age(self):
        """Entries written before retry_at existed must not be immortal either."""
        self._proven_evictable("aged-proven", "/home/user/agedblock")
        self.pager.block_eviction("aged-proven", "NO_ELIGIBLE_CONFIRMED_hostb_ASSET")
        self.assertEqual(self.pager.eviction_candidates(), [])
        with mock.patch.object(wp.time, "time", return_value=time.time() + 8 * 86400):
            self.assertNotIn("aged-proven", self.pager.eviction_blocks(7))
            self.assertIn("aged-proven", self.pager.eviction_blocks())
        # Inside the window it is still blocking: expiry must be time-based, not a waiver.
        with mock.patch.object(wp.time, "time", return_value=time.time() + 6 * 86400):
            self.assertIn("aged-proven", self.pager.eviction_blocks(7))

    def test_block_eviction_counts_repeats_and_rejects_bad_interval(self):
        """``count`` is what separates a one-off blip from a genuinely undeletable page.

        Without it every entry looked identical, so the <date> starvation investigation
        had no way to tell 1 refusal from 200.  Mirrors ``block_archive``.
        """
        first = self.pager.block_eviction("counted", "REFUSE_SOURCE_HAS_OPEN_HANDLES")
        self.assertEqual(first["count"], 1)
        second = self.pager.block_eviction("counted", "REFUSE_SOURCE_HAS_OPEN_HANDLES")
        self.assertEqual(second["count"], 2)
        self.assertNotIn("retry_at", second)
        with self.assertRaises(wp.PagerRefused):
            self.pager.block_eviction("counted", "REFUSE_X", retry_after_sec=0)

    def test_learning_dependencies_survive_fresh_page_table_sync(self):
        paths = ["/home/user/live-service", "/home/user/示例题库/整理"]
        records = {"hostb|" + p: {"host": "hostb", "path": p,
                   "mtime": time.time() - 30 * 86400} for p in paths}
        assets = [{"asset_id": "synthetic-live-" + str(i), "host": "hostb",
                   "original_path": p, "local_state": "replicated"}
                  for i, p in enumerate(paths)]
        self.pager.sync(records, assets, "mac")
        rows = self.pager.status()["rows"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["pinned"] == 1 and r["state"] == "PINNED" for r in rows))
        self.assertFalse(wp.auto_pin_applies("/home/user/示例题库/整理_old", 1))

    def test_drained_pool_above_trigger_is_warn_not_stuck(self):
        """Hysteresis window (trigger 10% < free < stop 15%) with nothing evictable."""
        self.pager.sync(self.record(), [], "mac")
        low = {"managed": {"total": 1000, "used": 920, "free": 80},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        self.pager.pool_status(disk_stats=low)  # arms eviction_active
        mid = {"managed": {"total": 1000, "used": 863, "free": 137},
               "isolated": {"total": 500, "used": 100, "free": 400}}
        alerts = {x["code"]: x for x in self.pager.alerts(disk_stats=mid)}
        self.assertIn("PAGER_PRESSURE_DRAINED", alerts)
        self.assertEqual(alerts["PAGER_PRESSURE_DRAINED"]["level"], "warn")
        self.assertNotIn("PAGER_PRESSURE_STUCK", alerts)
        self.assertNotIn("PAGER_EVICTING", alerts)
        codes = {x["code"] for x in self.pager.alerts(disk_stats=low)}
        self.assertIn("PAGER_PRESSURE_STUCK", codes)

    def test_semantic_stale_alert_respects_grace_period(self):
        changed = self.ws / "stale.txt"; changed.write_text("stale")
        self.pager.sync(self.record(), [], "mac")
        row = self.pager.mark_semantic_stale(
            "mac", str(self.ws), [str(changed)], "unit", "task")
        disk = {"managed": {"total": 1000, "used": 500, "free": 500},
                "isolated": {"total": 500, "used": 100, "free": 400}}
        now = float(row["semantic_stale_at"])
        self.assertNotIn("PAGER_SEMANTIC_STALE",
                         {x["code"] for x in self.pager.alerts(disk, now=now + 1799)})
        self.assertIn("PAGER_SEMANTIC_STALE",
                      {x["code"] for x in self.pager.alerts(disk, now=now + 1801)})

    def test_ws_restore_uses_version_head_and_rearchive_preserves_asset_id(self):
        ws_source = Path(__file__).with_name("ws").read_text(encoding="utf-8")
        self.assertIn("vault_v2_heads.json", ws_source)
        self.assertIn('cmd.extend(["--label", matching_assets.pop()])', ws_source)
        self.assertIn("assets = pager.load_assets()", ws_source)
        self.assertIn('status_rows[0]["annotation_status"] == "SYNC_FAILED"', ws_source)
        self.assertIn('"recovered_sync_failure": True', ws_source)
        self.assertIn('pager.Path("/tmp").resolve()', ws_source)

    def test_remote_content_fingerprint_matches_equal_trees_and_detects_change(self):
        one = self.root / "tree-one"; two = self.root / "tree-two"
        one.mkdir(); two.mkdir()
        (one / "a").write_bytes(b"same")
        (two / "a").write_bytes(b"same")
        first = wp.content_fingerprint(one)
        second = wp.content_fingerprint(two)
        self.assertEqual(first["sha256"], second["sha256"])
        (two / "a").write_bytes(b"changed")
        self.assertNotEqual(first["sha256"], wp.content_fingerprint(two)["sha256"])
        self.assertIn("content-fingerprint", Path(remote_archive.__file__).read_text())



class ArchiveBlockLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.pager = wp.WorkspacePager(root / "pages.db", manifest_dir=root / "m")

    def tearDown(self):
        self.tmp.cleanup()

    def test_transient_archive_refusal_retries_after_hour(self):
        with mock.patch.object(wp.time, "time", return_value=1000000):
            self.pager.block_archive("hostb|/a", "REFUSE_GIT_DIRTY", retry_after_sec=3600)
            self.assertIn("hostb|/a", self.pager.archive_blocks(7))
        with mock.patch.object(wp.time, "time", return_value=1003601):
            self.assertNotIn("hostb|/a", self.pager.archive_blocks(7))
            self.assertIn("hostb|/a", self.pager.archive_blocks())  # evidence retained

    def test_page_path_never_falls_through_to_child(self):
        import runpy
        ns = runpy.run_path(str(Path(__file__).with_name("ws")))
        cache = {"records": {"child": {"path": "/nonexistent/parent/child",
                    "host": "hostb", "name": "child"}}}
        with self.assertRaisesRegex(wp.PagerRefused, "WORKSPACE_NOT_FOUND"):
            ns["_page_record"](cache, "/nonexistent/parent")
        pg = mock.Mock()
        pg.status.return_value = {"rows": [{"path": "/nonexistent/parent",
                                           "host": "hostb"}]}
        self.assertEqual(ns["_page_record"](cache, "/nonexistent/parent", pg=pg)["path"],
                         "/nonexistent/parent")
        self.assertEqual(ns["_page_record"]({'records':{}}, 'hostb|/nonexistent/parent', pg=pg)['path'],
                         '/nonexistent/parent')
        source=Path(__file__).with_name('ws').read_text()
        call=source.split('if args.page_cmd in ("touch", "pin", "unpin"):',1)[1].splitlines()[1]
        self.assertIn('pg=pg',call)

    def test_block_unblock_and_expiry(self):
        self.assertEqual(self.pager.archive_blocks(), {})
        entry = self.pager.block_archive("hostb|/home/user/sim-env", "REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT x")
        self.assertEqual(entry["count"], 1)
        again = self.pager.block_archive("hostb|/home/user/sim-env", "REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT y")
        self.assertEqual(again["count"], 2)
        blocks = self.pager.archive_blocks()
        self.assertIn("hostb|/home/user/sim-env", blocks)
        self.assertIn("hostb|/home/user/sim-env", self.pager.archive_blocks(7))
        self.assertEqual(self.pager.archive_blocks(-1), {})
        self.assertTrue(self.pager.unblock_archive("hostb|/home/user/sim-env"))
        self.assertFalse(self.pager.unblock_archive("hostb|/home/user/sim-env"))
        self.assertEqual(self.pager.archive_blocks(), {})
        with self.pager.connect() as conn:
            events = [r[0] for r in conn.execute(
                "SELECT event FROM events WHERE event LIKE 'ARCHIVE_%' ORDER BY id")]
        self.assertEqual(events, ["ARCHIVE_BLOCKED", "ARCHIVE_BLOCKED", "ARCHIVE_UNBLOCKED"])

class RestorePythonTests(unittest.TestCase):
    """restore_python(): interpreter chosen by capability, never by PATH."""

    def test_first_candidate_that_imports_websocket_wins(self):
        probed = []

        def probe(py):
            probed.append(py)
            return py == "/bin/sh"
        chosen = wp.restore_python(candidates=(sys.executable, "/bin/sh"), probe=probe)
        self.assertEqual(chosen, "/bin/sh")
        self.assertEqual(probed, [sys.executable, "/bin/sh"])

    def test_missing_and_incapable_candidates_fail_closed(self):
        with self.assertRaises(wp.PagerRefused) as ctx:
            wp.restore_python(candidates=("/nonexistent/python", sys.executable),
                              probe=lambda py: False)
        msg = str(ctx.exception)
        self.assertIn("REFUSE_WEBSOCKET_CLIENT_MISSING", msg)
        self.assertIn("/nonexistent/python:missing", msg)
        self.assertIn(sys.executable + ":no-websocket-client", msg)

    def test_real_probe_finds_an_interpreter_on_this_host(self):
        import platform
        try:
            py = wp.restore_python(probe=None)
        except wp.PagerRefused as exc:
            if platform.system() != "Darwin":
                self.skipTest("restore runs on the Mac control plane only: %s" % exc)
            raise
        self.assertTrue(wp._probe_websocket(py), py)


class NoRestoreVerifyAlertTests(unittest.TestCase):
    """<date>: the restore-verification ledger and its alert are retired."""

    def test_alerts_never_emit_restore_verify_code(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        (root / "m").mkdir()
        pg = wp.WorkspacePager(root / "pages.db", manifest_dir=root / "m")
        disk = {"managed": {"total": 1000, "used": 800, "free": 200},
                "isolated": {"total": 500, "used": 100, "free": 400}}
        codes = {x["code"] for x in pg.alerts(disk_stats=disk)}
        self.assertNotIn("PAGER_RESTORE_VERIFY_FAILING", codes)
        source = Path(wp.__file__).read_text(encoding="utf-8")
        for token in ("PAGER_RESTORE_VERIFY_FAILING", "RESTORE_FAILURES", "restore_verify_failures"):
            self.assertNotIn(token, source)


class ReadOnlyEnginePinTests(unittest.TestCase):
    """Read-only engines must not be judged cold by a modification-time probe.

    <date>: engine-a / engine-b / engine-c / engine-d / model-cache and the
    tts-engine weights were all COLD and unpinned.  Model weights are never
    written, only read, so ``find -newermt`` reports them stone cold no matter
    how heavily the render and voice lines use them.  Every render task then
    faulted 19.4GB back in through the Mac, which is how the volume reached zero
    free bytes.
    """

    def test_every_engine_root_auto_pins(self):
        # Named explicitly: iterating the set alone would pass vacuously if the
        # set were ever emptied, which is exactly the regression to catch.
        expected = {"/home/user/engine-a", "/home/user/engine-b",
                    "/home/user/engine-c", "/home/user/engine-d",
                    "/home/user/model-cache", str(Path(wp.HOME) / "engine-e")}
        self.assertEqual(expected, set(wp.READ_ONLY_ENGINE_PATHS))
        for root in expected:
            self.assertTrue(wp.should_auto_pin(root), root)

    def test_weights_below_an_engine_root_also_pin(self):
        """The page table carries the leaves, not the roots: an exact-match-only
        rule would pin nothing that matters here."""
        for leaf in ("/home/user/engine-a/models/weights",
                     str(Path(wp.HOME) / "engine-e" / "checkpoints" / "gpt.pth")):
            self.assertTrue(wp.should_auto_pin(leaf), leaf)

    def test_unrelated_and_lookalike_paths_do_not_pin(self):
        for path in ("/home/user/engine-a-old",
                     "/home/user/示例项目/示例产线",
                     str(Path(wp.HOME) / "engine-e-backup")):
            self.assertFalse(wp.should_auto_pin(path), path)

    def test_historical_exact_match_roots_still_pin(self):
        self.assertTrue(wp.should_auto_pin(str(Path(wp.HOME) / ".coldstore")))
        self.assertTrue(wp.should_auto_pin("/home/user/tools"))

    # --- 钉住只保护本地副本(<date>):此前删掉的 7 个 Mac tts-engine 权重
    # 本地已不存在、云端已确认,库里却是 pinned=1。sync 按纯路径判据强设
    # state=PINNED,而 plan() 按 local_present==0 判 KEEP_COLD,两者直接打架;
    # 且一旦将来换入,pinned=1 会让 11GB 权重永不可淘汰。
    def test_auto_pin_requires_local_copy(self):
        leaf = str(Path(wp.HOME) / "engine-e" / "checkpoints" / "gpt.pth")
        self.assertTrue(wp.should_auto_pin(leaf), "路径判据本身不变")
        self.assertTrue(wp.auto_pin_applies(leaf, 1), "本地有副本才钉")
        self.assertFalse(wp.auto_pin_applies(leaf, 0), "只在云端的条目不得钉")
        self.assertFalse(wp.auto_pin_applies(leaf, -1), "存在性未知时不钉")

    def test_auto_pin_still_ignores_unrelated_paths_when_local(self):
        self.assertFalse(wp.auto_pin_applies("/home/user/engine-a-old", 1))

    # --- host 归一化(<date>):touch() 原样写入调用方给的 host,真实主机名
    # user-host-b-FORCE-DUO-X-WIFI7 因此进了权威库。后果不是显示难看:
    # storage_pool_for() 只认 "hostb",别的一律 EXTERNAL,于是这些行永久脱离
    # 分页管理,还与同一路径的规范行分裂成两条。当天在 hostb 实测到 2 行。
    def test_real_hostname_folds_to_canonical_name(self):
        import socket
        self.assertEqual(wp._host_name(socket.gethostname()), wp._self_host())

    def test_known_aliases_still_fold(self):
        for value, want in (("mac", "mac"), ("host-a", "mac"), ("host-a", "mac"),
                            ("hostb", "hostb"), ("linux", "hostb"), ("  MAC  ", "mac")):
            self.assertEqual(wp._host_name(value), want, value)

    def test_touch_refuses_unknown_host(self):
        # fail-closed:宁可拒绝写入,也不要把一条会脱离分页管理的行放进权威库
        import socket
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pg = wp.WorkspacePager(root / "pages.db", manifest_dir=root / "m")
            with self.assertRaises(wp.PagerRefused):
                pg.touch("some-random-box", str(root), "test")
            # 而本机真实主机名必须被折回、正常写入
            pg.touch(socket.gethostname(), str(root), "test")
            rows = pg.status(str(root))["rows"]
            self.assertEqual([r["host"] for r in rows], [wp._self_host()])


class PagerScratchIsolationTests(unittest.TestCase):
    """The pager must not manage its own restore staging.

    <date>: a restored tree carries the original workspace's HANDOFF.md, so
    the graph indexer registered three ``page_cache/restore-<asset>-*/engine-a``
    staging trees as HOT/WARM workspaces.  The pager was tracking its own scratch
    copies of an asset already in the cloud, and the rows outlived the
    directories -- claiming local_present=1 for paths that no longer existed.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pager = wp.WorkspacePager(self.root / "pages.db",
                                       manifest_dir=self.root / "m")

    def test_scratch_paths_are_recognised_on_any_host(self):
        for path in ("/Users/user/.coldstore/page_cache",
                     "/Users/user/.coldstore/page_cache/restore-x-abc/engine-a",
                     "/home/user/.coldstore/page_cache/hostb-wan-vace"):
            self.assertTrue(wp.is_pager_scratch(path), path)

    def test_real_workspaces_are_not_mistaken_for_scratch(self):
        for path in ("/Users/user/.coldstore/bin",
                     "/Users/user/page_cache",
                     "/home/user/engine-a",
                     "/home/user/.coldstore/dispatch/page_cache_notes"):
            self.assertFalse(wp.is_pager_scratch(path), path)

    def test_sync_skips_scratch_records_instead_of_registering_them(self):
        scratch = "/Users/user/.coldstore/page_cache/restore-a-1/engine-a"
        real = str(self.root / "realws")
        os.makedirs(real, exist_ok=True)
        records = {
            "mac|" + scratch: {"host": "mac", "path": scratch, "mtime": time.time()},
            "mac|" + real: {"host": "mac", "path": real, "mtime": time.time()},
        }
        self.pager.sync(records, [], "mac")
        with self.pager.connect() as conn:
            paths = [r[0] for r in conn.execute("SELECT path FROM pages")]
        self.assertEqual(paths, [real])

    def test_touch_refuses_scratch_rather_than_creating_a_row(self):
        scratch = "/Users/user/.coldstore/page_cache/restore-a-1/engine-a"
        with self.assertRaises(wp.PagerRefused) as ctx:
            self.pager.touch("mac", scratch, "ws page enter hit")
        self.assertIn("REFUSE_PAGER_SCRATCH_AS_WORKSPACE", str(ctx.exception))
        with self.pager.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM pages").fetchone()[0], 0)


class RestoreAssetFootprintTests(unittest.TestCase):
    """One fault-in must not cost two full copies of the asset.

    <date>: faulting in a 19.4GB engine left 14.6GB of encrypted blobs in the
    Baidu staging directory *and* 19.4GB of plaintext in the page cache.  The
    restore tool has always accepted ``--purge-downloaded-parts``; the pager just
    never passed it, so the Mac paid double and ran out of disk entirely.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tool = self.root / "cloud_asset_restore.py"
        self.tool.write_text("#\n", encoding="utf-8")
        self.out = self.root / "page_cache"
        self.asset = {"asset_id": "hostb-wan-vace", "cloud_verified": 1}
        self.identity = "a" * 64
        self.calls = []

    def _fake_run(self, argv, **kwargs):
        import types as _types
        self.calls.append(list(argv))
        (self.out / self.asset["asset_id"]).mkdir(parents=True, exist_ok=True)
        return _types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def _restore(self):
        from unittest import mock
        with mock.patch.object(wp, "RESTORE_TOOL", self.tool), \
             mock.patch.object(wp, "restore_version_identity", side_effect=lambda asset: self.identity), \
             mock.patch.object(wp, "restore_python", return_value=sys.executable), \
             mock.patch.object(wp.subprocess, "run", self._fake_run):
            return wp.restore_asset(self.asset, output_root=self.out)

    def test_blobs_are_purged_as_each_part_is_consumed(self):
        self._restore()
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--purge-downloaded-parts", self.calls[0])

    def test_restore_still_targets_the_page_cache_and_downloads(self):
        final = self._restore()
        self.assertEqual(final, self.out / self.asset["asset_id"])
        self.assertIn("--download", self.calls[0])
        self.assertIn(str(self.out), self.calls[0])

    def test_proven_cache_short_circuits_without_spawning_a_restore(self):
        self._restore()
        self.calls.clear()
        self._restore()
        self.assertEqual(self.calls, [])

    def test_new_version_discards_only_old_verified_cache(self):
        self._restore()
        self.identity = "b" * 64
        self._restore()
        self.assertEqual(len(self.calls), 2)

    def test_version_change_during_transfer_is_refused(self):
        with mock.patch.object(wp, "RESTORE_TOOL", self.tool), \
             mock.patch.object(wp, "restore_python", return_value=sys.executable), \
             mock.patch.object(wp.subprocess, "run", self._fake_run), \
             mock.patch.object(wp, "restore_version_identity", side_effect=["a" * 64, "b" * 64]):
            with self.assertRaisesRegex(wp.PagerRefused, "VERSION_CHANGED"):
                wp.restore_asset(self.asset, output_root=self.out)
        self.assertFalse((self.out / self.asset["asset_id"]).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
