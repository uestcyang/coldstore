import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import workspace_pager as pager


class PagerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.instance = pager.WorkspacePager(self.root / "pages.db",
                                             manifest_dir=self.root / "manifests")

    def cache(self, asset="synthetic"):
        final = self.root / asset
        final.mkdir()
        marker = self.root / (".restore-%s.json" % asset)
        marker.write_text(json.dumps({"asset_id": asset, "verdict": "RESTORE_PASS",
                                      "output": str(final)}))
        return final, marker

    def test_locked_cache_is_removed_without_touching_source(self):
        source = self.root / "source"
        source.mkdir()
        (source / "keep").write_text("synthetic")
        final, marker = self.cache()
        locked = final / "locked"
        locked.mkdir()
        (locked / "payload").write_text("synthetic")
        (final / "source_link").symlink_to(source, target_is_directory=True)
        locked.chmod(0)
        pager.discard_restore_cache("synthetic", self.root)
        self.assertFalse(final.exists())
        self.assertFalse(marker.exists())
        self.assertEqual((source / "keep").read_text(), "synthetic")

    def test_unproven_cache_is_retained(self):
        final, marker = self.cache()
        marker.unlink()
        with self.assertRaises(pager.PagerRefused):
            pager.discard_restore_cache("synthetic", self.root)
        self.assertTrue(final.exists())

    def test_wrong_asset_proof_is_rejected(self):
        final, marker = self.cache()
        marker.write_text(json.dumps({"asset_id": "different", "verdict": "RESTORE_PASS",
                                      "output": str(final)}))
        with self.assertRaises(pager.PagerRefused):
            pager.discard_restore_cache("synthetic", self.root)
        self.assertTrue(final.exists())

    def test_root_symlink_is_not_followed(self):
        target, marker = self.cache("target")
        (self.root / "synthetic").symlink_to(target, target_is_directory=True)
        with self.assertRaises(pager.PagerRefused):
            pager.discard_restore_cache("synthetic", self.root)
        self.assertTrue(target.exists())

    def test_asset_path_traversal_is_rejected(self):
        for asset in ("../outside", ".", "..", "/outside", "bad/name"):
            with self.subTest(asset=asset), self.assertRaises(pager.PagerRefused):
                pager.discard_restore_cache(asset, self.root)

    def test_missing_cache_is_idempotent(self):
        pager.discard_restore_cache("missing", self.root)

    def test_ssh_failure_cannot_produce_cold_evidence(self):
        with mock.patch.object(pager.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 255, "0\t/tmp/synthetic\n", "")):
            answer = self.instance._probe_tree_recent("hostb", ["/tmp/synthetic"], 3)
        self.assertIsNone(answer["/tmp/synthetic"])

    def test_linux_to_mac_routes_to_mac(self):
        with mock.patch.object(pager, "_self_host", return_value="hostb"), \
             mock.patch.object(pager.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 0, "", "")) as runner:
            self.instance._probe_tree_recent("mac", ["/tmp/synthetic"], 3)
        command = runner.call_args.args[0]
        self.assertIn("user@host-a", command)
        self.assertEqual(runner.call_args.kwargs["input"], "/tmp/synthetic\n")

    def test_unknown_host_and_injected_path_are_unprobeable(self):
        with mock.patch.object(pager.subprocess, "run") as runner:
            self.assertIsNone(self.instance._probe_tree_recent("unknown", ["/tmp/test"], 3)["/tmp/test"])
            self.instance._probe_tree_recent("mac", ["/tmp/test\necho bad"], 3)
        runner.assert_not_called()

    def test_find_error_is_not_cold(self):
        executable = self.root / "find"
        executable.write_text("#!/bin/sh\nexit 1\n")
        executable.chmod(0o700)
        with mock.patch.dict(os.environ, {"PATH": str(self.root) + ":" + os.environ["PATH"]}):
            answer = self.instance._probe_tree_recent(pager._self_host(), [str(self.root)], 3)
        self.assertIsNone(answer[str(self.root)])

    def seed_cold(self, probe_age=0):
        workspace = self.root / "workspace"
        workspace.mkdir()
        self.instance.sync({"mac|" + str(workspace): {"host": "mac", "path": str(workspace),
                           "mtime": time.time() - 20 * 86400}}, [], "mac")
        window = self.instance.policy.get("liveness_window_days") or self.instance.policy.get("hot_days", 3)
        with self.instance.connect() as connection:
            connection.execute("UPDATE pages SET tree_recent=0,tree_probed_at=?,tree_probe_days=?",
                               (time.time() - probe_age, window))
        return workspace

    def test_expired_cold_evidence_is_not_usable(self):
        self.seed_cold(7 * 3600)
        self.assertEqual(self.instance.plan()[0]["action"], "LIVENESS_PROBE_REQUIRED")

    def test_failed_refresh_invalidates_previous_cold_evidence(self):
        workspace = self.seed_cold()
        with mock.patch.object(self.instance, "_probe_tree_recent", return_value={str(workspace): None}):
            self.instance.refresh_tree_liveness(ttl_sec=0)
        self.assertIsNone(self.instance.status()["rows"][0]["tree_recent"])
        self.assertEqual(self.instance.plan()[0]["action"], "LIVENESS_PROBE_REQUIRED")

    def test_version_identity_changes_with_head_not_catalog_timestamp(self):
        heads = self.root / "vault_v2_heads.json"
        asset = {"asset_id": "synthetic", "indexed_at": 1}
        heads.write_text(json.dumps({"heads": {"synthetic": {"version_id": "a" * 64, "root": "/synthetic"}}}))
        with mock.patch.object(pager, "CLOUD_WORKSPACE", self.root):
            first = pager.restore_version_identity(asset)
            asset["indexed_at"] = 2
            self.assertEqual(first, pager.restore_version_identity(asset))
            heads.write_text(json.dumps({"heads": {"synthetic": {"version_id": "b" * 64, "root": "/synthetic"}}}))
            self.assertNotEqual(first, pager.restore_version_identity(asset))

    def test_missing_or_damaged_version_authority_is_refused(self):
        with mock.patch.object(pager, "CLOUD_WORKSPACE", self.root):
            with self.assertRaises(pager.PagerRefused):
                pager.restore_version_identity({"asset_id": "synthetic"})
            (self.root / "vault_v2_heads.json").write_text('{')
            with self.assertRaises(pager.PagerRefused):
                pager.restore_version_identity({"asset_id": "synthetic"})

    def test_cache_reuse_refuses_symlink_and_mismatched_output(self):
        asset = {"asset_id": "synthetic", "cloud_verified": True}
        final, marker = self.cache()
        tool = self.root / "tool"
        tool.touch()
        with mock.patch.object(pager, "RESTORE_TOOL", tool), mock.patch.object(
                pager, "restore_version_identity", return_value="version"):
            marker.write_text(json.dumps({"asset_id": "synthetic", "verdict": "RESTORE_PASS",
                                          "output": "/elsewhere", "version_fingerprint": "version"}))
            with self.assertRaisesRegex(pager.PagerRefused, "BAD_RESTORE_CACHE_PROOF"):
                pager.restore_asset(asset, self.root)
            final.rmdir()
            final.symlink_to(self.root / "absent", target_is_directory=True)
            with self.assertRaisesRegex(pager.PagerRefused, "SYMLINK"):
                pager.restore_asset(asset, self.root)
            final.unlink()
            marker.unlink()
            marker.symlink_to(tool)
            with self.assertRaisesRegex(pager.PagerRefused, "SYMLINK"):
                pager.restore_asset(asset, self.root)


if __name__ == "__main__":
    unittest.main()
