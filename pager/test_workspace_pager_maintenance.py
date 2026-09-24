#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import inspect
import json
import re
import sqlite3
import tempfile
import shutil
import unittest
from unittest import mock
import pathlib
from pathlib import Path

import workspace_pager_maintenance as maintenance


class FoundryStageTests(unittest.TestCase):
    def make_stage(self, root: Path, device: str = "cpu", vram: int = 0) -> Path:
        (root / "function_foundry_index.jsonl").write_text(
            json.dumps({"kind": "function_tool"}) + "\n", encoding="utf-8"
        )
        (root / "function_foundry_storage.json").write_text(
            json.dumps({"schema_version": 1, "storage": []}), encoding="utf-8"
        )
        (root / "capability_cards.jsonl").write_text(
            json.dumps({"card_id": "fixture:one"}) + "\n", encoding="utf-8"
        )
        (root / "capability_index_meta.json").write_text(json.dumps({
            "card_count": 1, "cpu_only_enforced": True, "embedding_model": "fixture",
            "embedding_dim": 2, "embedding_device": device, "embedding_vram_mib": vram,
            "cards_sha256": "sha256:fixture",
            "router_engine": maintenance.CAPABILITY_ROUTER_ENGINE,
            "router_package_version": maintenance.CAPABILITY_ROUTER_PACKAGE_VERSION,
            "router_utterance_count": 1,
            "router_utterances_sha256": "sha256:utterances",
        }), encoding="utf-8")
        with sqlite3.connect(root / "capability_index.sqlite3") as conn:
            conn.execute("CREATE TABLE capabilities(card_id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO capabilities VALUES('fixture:one')")
            conn.execute("CREATE TABLE semantic_router_utterances(route_name TEXT)")
            conn.execute("INSERT INTO semantic_router_utterances VALUES('fixture:one')")
        index_sha256 = hashlib.sha256(
            (root / "capability_index.sqlite3").read_bytes()
        ).hexdigest()
        (root / "capability_router_manifest.json").write_text(json.dumps({
            "engine": maintenance.CAPABILITY_ROUTER_ENGINE,
            "package_version": maintenance.CAPABILITY_ROUTER_PACKAGE_VERSION,
            "source_commit": maintenance.CAPABILITY_ROUTER_SOURCE_COMMIT,
            "wheel_sha256": maintenance.CAPABILITY_ROUTER_WHEEL_SHA256,
            "litellm_security_floor": maintenance.CAPABILITY_ROUTER_LITELLM_FLOOR,
            "litellm_locked_version": maintenance.CAPABILITY_ROUTER_LITELLM_VERSION,
            "offline_cost_map_enforced": True,
            "score_threshold": maintenance.CAPABILITY_ROUTER_SCORE_THRESHOLD,
            "aggregation": maintenance.CAPABILITY_ROUTER_AGGREGATION,
            "retrieval_contract_version": maintenance.CAPABILITY_RETRIEVAL_CONTRACT_VERSION,
            "cpu_only_enforced": True,
            "card_count": 1,
            "cards_sha256": "sha256:fixture",
            "utterance_count": 1,
            "utterances_sha256": "sha256:utterances",
            "index_sha256": index_sha256,
        }), encoding="utf-8")
        return root

    def test_valid_stage_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = maintenance.validate_foundry_stage(self.make_stage(Path(raw)))
        self.assertEqual(result, {"artifacts": 6, "repository_rows": 1,
                                  "capability_cards": 1, "router_utterances": 1})

    def test_gpu_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = self.make_stage(Path(raw), device="cuda", vram=1024)
            with self.assertRaisesRegex(RuntimeError, "NOT_CPU_ONLY"):
                maintenance.validate_foundry_stage(stage)

    def test_card_id_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = self.make_stage(Path(raw))
            with sqlite3.connect(stage / "capability_index.sqlite3") as conn:
                conn.execute("UPDATE capabilities SET card_id='fixture:other'")
            with self.assertRaisesRegex(RuntimeError, "CARDINALITY"):
                maintenance.validate_foundry_stage(stage)

    def test_router_manifest_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stage = self.make_stage(Path(raw))
            manifest = json.loads((stage / "capability_router_manifest.json").read_text())
            manifest["index_sha256"] = "0" * 64
            (stage / "capability_router_manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "ROUTER_MANIFEST_MISMATCH"):
                maintenance.validate_foundry_stage(stage)


class PressureEvictionTests(unittest.TestCase):
    class FakePager:
        def __init__(self, *, active=True, candidates=True):
            self.active = active
            self.has_candidates = candidates
            self.evicted = 0

        def pool_status(self):
            active = self.active and self.evicted == 0
            return {"managed": {
                "free_ratio": 0.08 if active else 0.16,
                "trigger_free_ratio": 0.10,
                "stop_free_ratio": 0.15,
                "eviction_active": active,
            }}

        def eviction_candidates(self):
            if not self.has_candidates or self.evicted:
                return []
            return [{"asset_id": "asset-one", "size_bytes": 123}]

    @staticmethod
    def cfg(**overrides):
        value = {
            "pool_migration_state": "COMPLETE", "evict_enabled": True,
            "max_evictions_per_run": 4, "archive_timeout_sec": 60,
        }
        value.update(overrides)
        return value

    def test_capacity_shortfall_never_becomes_drained_success(self):
        pg = self.FakePager(active=False, candidates=False)
        pg.pool_status = lambda: {'managed': dict(free_ratio=.12, trigger_free_ratio=.10,
                capacity_pending=True, capacity_gap_bytes=110, target_free_bytes=230)}
        report = maintenance._no_candidate_outcome(pg, {})
        self.assertEqual(report['status'], 'CAPACITY_BLOCKED_NO_ELIGIBLE_PAGE')
        self.assertEqual(report['capacity_gap_bytes'], 110)

    def test_real_ledger_drives_recovery_above_watermark_without_waiving_candidates(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            pg = maintenance.pager.WorkspacePager(Path(tmp)/'pages.db')
            pg.request_capacity('asset-pool-v3', 230, batch_id='batch-0003',
                                manifest_sha256='a'*64)
            disk = {'managed': {'total': 1000, 'used': 880, 'free': 120},
                    'isolated': {'total': 500, 'used': 100, 'free': 400}}
            pool_status = pg.pool_status
            pg.pool_status = lambda: pool_status(disk)
            candidates = [{'asset_id':'synthetic-confirmed-page','size_bytes':110}]
            pg.eviction_candidates = lambda: candidates
            def runner(args, timeout):
                self.assertEqual(args[-1], 'synthetic-confirmed-page')
                disk['managed'].update(free=230, used=770)
                candidates.clear()
                return type('R', (), dict(returncode=0, stdout='EVICT_PASS source_deleted=true', stderr=''))()
            with mock.patch.object(maintenance, 'reconcile_eviction_blocks', return_value={}):
                result = maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)
            self.assertEqual(result['status'], 'RECOVERED')
            self.assertEqual(result['net_free_change_bytes'], 110)
            self.assertEqual(result['remaining_gap_bytes'], 0)
            self.assertFalse(pg.pool_status()['managed']['eviction_active'])

    def test_cycle_deletes_until_stop_watermark(self):
        pg = self.FakePager()
        calls = []

        def runner(args, timeout):
            calls.append((args, timeout))
            pg.evicted += 1
            return type("Result", (), {
                "returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": "",
            })()

        result = maintenance.pressure_eviction_cycle(
            self.cfg(), pg=pg, runner=runner
        )
        self.assertEqual((result["status"], result["evicted"]), ("RECOVERED", 1))
        self.assertEqual(calls[0][0][-3:], ["--execute-delete", "--asset", "asset-one"])

    def test_shadow_reports_candidate_without_deleting(self):
        pg = self.FakePager()
        result = maintenance.pressure_eviction_cycle(
            self.cfg(), shadow=True, pg=pg,
            runner=lambda *_: self.fail("shadow must not invoke deletion"),
        )
        self.assertEqual(
            (result["status"], result["next_asset_id"], result["evicted"]),
            ("WOULD_EVICT", "asset-one", 0),
        )

    def test_zero_exit_without_delete_proof_is_not_counted(self):
        from unittest import mock
        for text in ('', 'NO_PRESSURE_EVICTION', 'EVICT_PASS source_deleted=false'):
            result=type('Result',(),{'returncode':0,'stdout':text,'stderr':''})()
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError,'PROOF_MISSING'):
                maintenance.pressure_eviction_cycle(self.cfg(),pg=self.FakePager(),
                    runner=mock.Mock(return_value=result))

    def test_old_zero_exit_lock_wait_is_not_counted(self):
        from unittest import mock
        result=type('Result',(),{'returncode':0,'stdout':'WAIT_ASSET_OPERATION_LOCK','stderr':''})()
        out=maintenance.pressure_eviction_cycle(self.cfg(),pg=self.FakePager(),
            runner=mock.Mock(return_value=result))
        self.assertEqual(out['evicted'],0)
        self.assertEqual(out['status'],'WAIT_ASSET_OPERATION_LOCK')

    def test_budget_returns_completed_progress_before_next_asset(self):
        pg = self.FakePager()
        calls = []
        ticks = iter([0, 901])

        def runner(args, timeout):
            calls.append(args)
            return type("Result", (), {
                "returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": "",
            })()

        result = maintenance.pressure_eviction_cycle(
            self.cfg(), pg=pg, runner=runner, clock=lambda: next(ticks))
        self.assertEqual(result["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(result["evicted"], 1)
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["final_free_ratio"], 0.08)

    def test_draining_migration_is_a_noop_while_disabled(self):
        result = maintenance.pressure_eviction_cycle(self.cfg(
            pool_migration_state="DRAINING", evict_enabled=False
        ))
        self.assertEqual(result["status"], "MIGRATION_DRAINING")

    def test_evict_tool_routes_v3_registered_batches_only(self):
        import sqlite3 as _sqlite3
        tmp = Path(tempfile.mkdtemp())
        v3_db = tmp / "logical_vault_v3.sqlite3"
        with _sqlite3.connect(v3_db) as conn:
            conn.execute("CREATE TABLE batches(batch_id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO batches VALUES('batch-0002')")
        v3_tool = tmp / "logical_vault_v3_evict.py"
        v2_tool = tmp / "cloud_asset_evict_once.py"
        v3_tool.write_text("#\n"); v2_tool.write_text("#\n")
        kw = dict(v3_db=v3_db, v3_tool=v3_tool, v2_tool=v2_tool)
        self.assertEqual(maintenance.evict_tool_for("hostb-asset-pool-v3-batch-0002", **kw), v3_tool)
        # registered by name pattern but absent from the v3 control plane -> v2 owns it
        self.assertEqual(maintenance.evict_tool_for("hostb-asset-pool-v3-batch-0001", **kw), v2_tool)
        self.assertEqual(maintenance.evict_tool_for("hostb-dataset-a", **kw), v2_tool)
        v3_tool.unlink()
        with self.assertRaises(RuntimeError):
            maintenance.evict_tool_for("hostb-asset-pool-v3-batch-0002", **kw)
        shutil.rmtree(tmp)

    def test_pressure_with_only_hot_grace_pages_waits_instead_of_failing(self):
        class WaitingPager(self.FakePager):
            def __init__(self):
                super().__init__(candidates=False)

            def pressure_waiting(self):
                return [{"asset_id": "hot-proven", "size_bytes": 5, "reason": "hot_grace",
                         "eligible_at": 1.0}]

        result = maintenance.pressure_eviction_cycle(
            self.cfg(), pg=WaitingPager(),
            runner=lambda *_: self.fail("waiting must not invoke deletion"),
        )
        self.assertEqual((result["status"], result["evicted"]), ("WAITING_HOT_GRACE", 0))
        self.assertEqual(result["waiting"][0]["asset_id"], "hot-proven")
        self.assertEqual(result["earliest_eligible_at"], 1.0)

    def test_executor_refusal_is_blocked_and_skipped_not_fatal(self):
        """<date>: a REFUSE_* from the executor must not starve the queue behind it."""
        class TwoPager(self.FakePager):
            def __init__(self):
                super().__init__()
                self.blocks = {}

            def eviction_candidates(self):
                if self.evicted:
                    return []
                # refused-one is the *largest* page so the <date> pressure order
                # (bytes first) still puts the refusal at the head of the queue: the
                # scenario under test is "a refusal at the head must not starve the rest".
                return [c for c in (
                    {"asset_id": "refused-one", "size_bytes": 500},
                    {"asset_id": "asset-two", "size_bytes": 123},
                ) if c["asset_id"] not in self.blocks]

            def block_eviction(self, asset_id, reason):
                self.blocks[asset_id] = reason

        pg = TwoPager()
        calls = []

        def runner(args, timeout):
            calls.append(args[-1])
            if args[-1] == "refused-one":
                return type("R", (), {"returncode": 1, "stdout": "CATALOG_OK\n",
                                      "stderr": "REFUSE_SOURCE_PATH_TOO_BROAD\n"})()
            pg.evicted += 1
            return type("R", (), {"returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": ""})()

        result = maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)
        self.assertEqual(calls, ["refused-one", "asset-two"])
        self.assertEqual((result["status"], result["evicted"]), ("RECOVERED", 1))
        self.assertEqual([r["asset_id"] for r in result["refused"]], ["refused-one"])
        self.assertIn("REFUSE_SOURCE_PATH_TOO_BROAD", pg.blocks["refused-one"])
        self.assertEqual(len(result["attempts"]), 2)

    def test_pressure_order_is_largest_first_then_coldest(self):
        """<date>: under pressure bytes decide, coldness only breaks ties.

        Fixed per-executor overhead (~2-3 min) made the coldest-first order evict five
        ~100MB pages per 900s tick while 10GB pages sat behind them; 31GB to the stop
        line would have taken ~200h.
        """
        cands = [
            {"asset_id": "small-oldest", "size_bytes": 5, "last_access": 10},
            {"asset_id": "big-newer", "size_bytes": 10_000, "last_access": 500},
            {"asset_id": "big-older", "size_bytes": 10_000, "last_access": 100},
            {"asset_id": "mid", "size_bytes": 2_000, "last_access": 1},
            {"asset_id": "nosize", "last_access": 0},
        ]
        self.assertEqual(
            [c["asset_id"] for c in maintenance.pressure_order(cands)],
            ["big-older", "big-newer", "mid", "small-oldest", "nosize"],
        )

        class ThreePager(self.FakePager):
            def eviction_candidates(self):
                if self.evicted:
                    return []
                return [
                    {"asset_id": "small-oldest", "size_bytes": 5, "last_access": 10},
                    {"asset_id": "big", "size_bytes": 10_000, "last_access": 500},
                    {"asset_id": "mid", "size_bytes": 2_000, "last_access": 1},
                ]

        pg = ThreePager()
        shadow = maintenance.pressure_eviction_cycle(
            self.cfg(), shadow=True, pg=pg,
            runner=lambda *_: self.fail("shadow must not invoke deletion"))
        self.assertEqual(shadow["next_asset_id"], "big")

        calls = []

        def runner(args, timeout):
            calls.append(args[-1])
            pg.evicted += 1
            return type("R", (), {"returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": ""})()

        result = maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)
        self.assertEqual(calls, ["big"])
        self.assertEqual((result["status"], result["evicted"]), ("RECOVERED", 1))

    def test_transient_executor_failure_still_aborts(self):
        pg = self.FakePager()

        def runner(args, timeout):
            return type("R", (), {"returncode": 255, "stdout": "",
                                  "stderr": "ssh: connect to host host-b: Connection refused"})()

        with self.assertRaisesRegex(RuntimeError, "PRESSURE_EVICTION_FAILED"):
            maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)

    def test_all_candidates_refused_fails_closed_with_receipt(self):
        pg = self.FakePager()
        pg.block_eviction = lambda a, r: None

        def runner(args, timeout):
            return type("R", (), {"returncode": 1, "stdout": "NO_ELIGIBLE_CONFIRMED_hostb_ASSET\n",
                                  "stderr": ""})()

        with self.assertRaisesRegex(RuntimeError, "PRESSURE_EVICTION_REFUSED"):
            maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)

    def test_progress_then_drained_keeps_receipt(self):
        """Evicting one page and then running out of candidates must not raise."""
        class DrainPager(self.FakePager):
            def pool_status(self):
                return {"managed": {"free_ratio": 0.08, "trigger_free_ratio": 0.10,
                                    "stop_free_ratio": 0.15, "eviction_active": True}}

            def pressure_waiting(self):
                return []

        pg = DrainPager()

        def runner(args, timeout):
            pg.evicted += 1
            return type("R", (), {"returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": ""})()

        result = maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)
        self.assertEqual((result["status"], result["evicted"]), ("LIMIT_REACHED", 1))

    def test_successfully_evicted_asset_is_never_retried_in_same_cycle(self):
        class StickyPager(self.FakePager):
            def pool_status(self):
                return {"managed": {"free_ratio": 0.08, "trigger_free_ratio": 0.10,
                                    "stop_free_ratio": 0.15, "eviction_active": True}}

            def eviction_candidates(self):
                # simulates a page row not yet refreshed after the executor's own mark
                return [{"asset_id": "asset-one", "size_bytes": 123}]

            def pressure_waiting(self):
                return []

        pg = StickyPager()
        calls = []

        def runner(args, timeout):
            calls.append(args[-1])
            return type("R", (), {"returncode": 0, "stdout": "EVICT_PASS source_deleted=true", "stderr": ""})()

        result = maintenance.pressure_eviction_cycle(self.cfg(), pg=pg, runner=runner)
        self.assertEqual(calls, ["asset-one"])
        self.assertEqual((result["status"], result["evicted"]), ("LIMIT_REACHED", 1))

    def test_drained_pool_above_trigger_returns_receipt_not_error(self):
        class DrainedPager(self.FakePager):
            def __init__(self):
                super().__init__(candidates=False)

            def pool_status(self):
                return {"managed": {"free_ratio": 0.137, "trigger_free_ratio": 0.10,
                                    "stop_free_ratio": 0.15, "eviction_active": True}}

            def pressure_waiting(self):
                return []

        result = maintenance.pressure_eviction_cycle(
            self.cfg(), pg=DrainedPager(),
            runner=lambda *_: self.fail("drained pool must not invoke deletion"),
        )
        self.assertEqual((result["status"], result["evicted"]), ("DRAINED", 0))
        self.assertAlmostEqual(result["final_free_ratio"], 0.137)

    def test_pressure_without_candidate_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "WITHOUT_ELIGIBLE_WARM_PAGE"):
            maintenance.pressure_eviction_cycle(
                self.cfg(), pg=self.FakePager(candidates=False)
            )


class MainPassOrderingTests(unittest.TestCase):
    """Structural regression agent-b for the self-inflicted-deadlock class of bug.

    pressure_eviction_cycle() intentionally raises (fail-closed) whenever
    eviction_candidates() is still empty, and main()'s bare
    `except Exception: ... raise` aborts everything after that call. Any
    step that is the *only* way to ever populate eviction_candidates()
    (archiving -> cloud_verified) must therefore run *before*
    pressure_eviction_cycle() is invoked, or the
    pipeline permanently deadlocks: the gate keeps failing, which keeps the
    one step that could clear the gate from ever running. This happened
    twice in production (archiving on <date>, restore verification on
    <date>) because nothing enforced the ordering after review. Assert
    the ordering structurally so a future edit that moves either step back
    below the gate call fails CI instead of silently reintroducing the
    deadlock.
    """

    def test_archive_precedes_pressure_gate(self):
        source = inspect.getsource(maintenance.main)
        # main() calls pressure_eviction_cycle() twice: once in the early
        # --pressure-only branch (which returns immediately and never touches
        # archive), and once in the full-pass flow below the archive step.
        # The ordering guarantee only applies
        # to the *full-pass* call, so take the last real call site, not the
        # first (which would be the unrelated --pressure-only branch and
        # would make this assertion fail for the wrong reason).
        gate_matches = list(re.finditer(
            r'receipt\["eviction"\]\s*=\s*pressure_eviction_cycle\(', source
        ))
        self.assertGreaterEqual(
            len(gate_matches), 2,
            "expected both the --pressure-only call and the full-pass call "
            "to receipt['eviction'] = pressure_eviction_cycle(...)",
        )
        gate_pos = gate_matches[-1].start()

        # <date>: the single "archive plan()[0]" step became archive_drain();
        # the full-pass call site is the last occurrence (the earlier one is the
        # --archive-only branch).
        archive_pos = source.rindex('archive_stage(')
        self.assertLess(
            archive_pos, gate_pos,
            "archive step must run before pressure_eviction_cycle() "
            "(<date> deadlock: archiving is the only way to ever "
            "populate eviction_candidates())",
        )

    def test_no_restore_verification_stage_anywhere(self):
        """Operator policy "trust-the-cloud".

        The download-back drain that used to sit between archive_stage and the
        pressure gate is gone for good: no restore_stage/restore_drain, no
        --verify-only entry point, no restore-failure ledger, no staging-space
        admission.  A page becomes evictable on cloud confirmation + archive-time
        snapshot alone, so nothing in the maintenance pass may spawn a Baidu
        download.
        """
        source = Path(maintenance.__file__).read_text(encoding="utf-8")
        for token in ("restore_stage(", "def restore_drain", "reconcile_restore_contracts",
                      "--verify-only", "verify_only", "RESTORE_FAILURES", "staging_source_cap",
                      "--verify-initial-only", "--verify-metadata-only", "INITIAL_RESTORE_REQUIRED",
                      "cloud_asset_restore.py", "page\", \"verify\""):
            self.assertNotIn(token, source, token)
        cycle = Path(maintenance.BIN / "workspace_pager_cycle.py").read_text(encoding="utf-8")
        self.assertNotIn("'verify'", cycle)
        self.assertIn("choices=('archive', 'pressure')", cycle)
        self.assertEqual(maintenance.main.__code__.co_varnames.count("restore_stage"), 0)


class ArchiveDrainTests(unittest.TestCase):
    """archive_drain(): serial, block-aware, single-writer, budget/limit bounded."""

    class FakePager:
        def pool_status(self):  # <date>: archive_stage publishes the pager-priority flag
            return {"managed": {"eviction_active": False, "free_ratio": 0.3}}

        def __init__(self, blocked=None):
            self.blocked = dict(blocked or {})
            self.block_calls = []

        def archive_blocks(self, max_age_days=None):
            return dict(self.blocked)

        def block_archive(self, key, reason, retry_after_sec=None):
            self.block_calls.append((key, reason))
            self.blocked[key] = {"reason": reason, "at": 0, "count": 1}
            if retry_after_sec is not None:
                self.blocked[key]["retry_after_sec"] = retry_after_sec
            return self.blocked[key]

    class Proc:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    @staticmethod
    def cfg(**overrides):
        value = {"archive_mode": "copy", "cold_days": 15, "archive_timeout_sec": 60,
                 "archive_block_days": 7}
        value.update(overrides)
        return value

    @staticmethod
    def plan(*keys):
        return [{"workspace_key": "hostb|" + k, "path": k, "action": "ARCHIVE_CANDIDATE"}
                for k in keys]

    def runner_for(self, outcomes):
        calls = []

        def runner(cmd, timeout):
            calls.append(cmd)
            path = cmd[3]
            rc, err = outcomes[path]
            return self.Proc(rc, "", err)
        return runner, calls

    def test_deterministic_refusal_is_blocked_and_drain_continues(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({
            "/a": (2, "REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_REMOTE_CONSISTENCY rc=2 "
                      "detail=REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT markers=['leveldb']"),
            "/b": (0, ""),
        })
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b"), [], shadow=False, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(report["status"], "BLOCKED_PENDING")
        self.assertEqual((report["archived"], report["blocked"], report["skipped"]), (1, 1, 0))
        self.assertEqual([c[0] for c in pg.block_calls], ["hostb|/a"])
        self.assertIn("REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT", pg.block_calls[0][1])
        self.assertEqual([c[3] for c in calls], ["/a", "/b"])
        self.assertIn("--execute", calls[1])
        self.assertEqual([a["outcome"] for a in report["attempts"]], ["blocked", "archived"])

    def test_live_tree_deferral_preserves_proof_and_does_not_count_as_upload(self):
        pg = self.FakePager()
        reason = 'REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_PAGE_TREE_LIVE host=hostb path=/a window_days=3.0'
        runner, calls = self.runner_for({'/a': (2, reason), '/b': (0, '')})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan('/a', '/b'), [], shadow=False,
            budget_sec=600, max_items=10, runner=runner, busy=lambda: None,
            clock=lambda: 0.0)
        self.assertEqual(report['status'], 'LIVE_DEFERRED')
        self.assertEqual(report['archived'], 1)
        self.assertEqual(report['live_deferred'], 1)
        self.assertEqual(report['retry_queue'], 0)
        self.assertEqual(maintenance.archive_exit_code(report), 0)
        self.assertIn(reason, report['attempts'][0]['tail'])
        self.assertEqual(pg.blocked['hostb|/a']['retry_after_sec'], 3600)
        calls.clear()
        maintenance.archive_drain(self.cfg(), pg, self.plan('/a'), [], shadow=False,
                                  budget_sec=600, max_items=10, runner=runner,
                                  busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(calls, [])

    def test_live_marker_cannot_hide_unknown_mixed_or_transport_failures(self):
        live = 'REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_PAGE_TREE_LIVE host=hostb path=/a window_days=3.0'
        for rc, reason in ((2, 'REFUSE_PAGE_LIVENESS_UNKNOWN'),
                           (2, live + '\nSSH connection failed'),
                           (255, live), (2, 'HTTP 503')):
            with self.subTest(reason=reason, rc=rc):
                pg = self.FakePager()
                report = maintenance.archive_drain(
                    self.cfg(), pg, self.plan('/a'), [], shadow=False,
                    budget_sec=600, max_items=10,
                    runner=self.runner_for({'/a': (rc, reason)})[0],
                    busy=lambda: None, clock=lambda: 0.0)
                self.assertEqual(report['live_deferred'], 0)
                self.assertEqual(maintenance.archive_exit_code(report), 2)

    def test_blocked_pages_are_skipped_before_any_call(self):
        pg = self.FakePager(blocked={"hostb|/a": {"reason": "x", "at": 0}})
        runner, calls = self.runner_for({"/b": (0, "")})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b"), [], shadow=False, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual([c[3] for c in calls], ["/b"])
        self.assertEqual(report["blocked_before"], 1)
        self.assertEqual(report["queue"], 1)

    def test_dirty_or_drifting_pages_backoff_without_monopolizing_writer(self):
        for reason in ("REFUSE_GIT_DIRTY", "REFUSE_SQLITE_NOT_QUIESCENT",
                       "REFUSE_SNAPSHOT_DRIFT"):
            with self.subTest(reason=reason):
                pg = self.FakePager()
                runner, calls = self.runner_for({"/a": (2, reason), "/b": (0, "")})
                report = maintenance.archive_drain(
                    self.cfg(), pg, self.plan("/a", "/b"), [], shadow=False,
                    budget_sec=600, max_items=10, runner=runner, busy=lambda: None,
                    clock=lambda: 0.0)
                self.assertEqual(report["archived"], 1)
                self.assertEqual(report["status"], "RETRY_PENDING")
                self.assertEqual(report["remaining_queue"], 0)
                self.assertEqual(pg.blocked["hostb|/a"]["retry_after_sec"], 3600)
                again = maintenance.archive_drain(
                    self.cfg(), pg, self.plan("/a"), [], shadow=False,
                    budget_sec=600, max_items=10, runner=runner, busy=lambda: None,
                    clock=lambda: 0.0)
                self.assertEqual(again["queue"], 0)

    def test_remote_wrapper_preserves_retryable_leaf_reason(self):
        for leaf in ("REFUSE_GIT_DIRTY repo=/work sample=['M notes.md']",
                     "REFUSE_SQLITE_UNCHECKPOINTED db=/work/data.db",
                     "REFUSE_SNAPSHOT_DRIFT before={} after={}"):
            with self.subTest(leaf=leaf):
                reason = "REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_REMOTE_CONSISTENCY rc=2 detail=" + leaf
                pg = self.FakePager()
                runner, calls = self.runner_for({'/a': (2, reason), '/b': (0, '')})
                report = maintenance.archive_drain(
                    self.cfg(), pg, self.plan('/a', '/b'), [], shadow=False,
                    budget_sec=600, max_items=10, runner=runner,
                    busy=lambda: None, clock=lambda: 0.0)
                self.assertEqual(pg.blocked['hostb|/a'].get('retry_after_sec'), 3600)
                self.assertEqual(report['retry_queue'], 1)
                self.assertEqual(report['archived'], 1)
                self.assertEqual([c[3] for c in calls], ['/a', '/b'])

    def test_blocked_backlog_is_not_idle_or_success(self):
        pg = self.FakePager(blocked={'hostb|/a': {'reason': 'REFUSE_GIT_DIRTY', 'at': 0}})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan('/a'), [], shadow=False,
            budget_sec=600, max_items=10, runner=mock.Mock(), busy=lambda: None)
        self.assertEqual(report['status'], 'BLOCKED_PENDING')
        self.assertEqual(report['blocked_candidates'], 1)
        self.assertEqual(maintenance.archive_exit_code(report), 2)

    def test_retry_marker_in_path_does_not_override_permanent_refusal(self):
        reason = ('REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_REMOTE_CONSISTENCY rc=2 '
                  'detail=REFUSE_GIT_PARTIAL_ROOT target=/x/REFUSE_GIT_DIRTY repo=/x')
        self.assertFalse(maintenance.retryable_archive_refusal(reason))

    def test_blocked_unrelated_page_does_not_make_empty_plan_fail(self):
        pg = self.FakePager(blocked={'hostb|/old': {'reason': 'REFUSE_GIT_DIRTY', 'at': 0}})
        report = maintenance.archive_drain(
            self.cfg(), pg, [], [], shadow=False, budget_sec=600,
            max_items=10, runner=mock.Mock(), busy=lambda: None)
        self.assertEqual(report['status'], 'IDLE')

    def test_deferred_live_tree_is_not_a_failure_while_cooling_down(self):
        pg = self.FakePager(blocked={'hostb|/a': {'reason':
            'REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_PAGE_TREE_LIVE host=hostb path=/a window_days=3.0', 'at': 0}})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan('/a'), [], shadow=False,
            budget_sec=600, max_items=10, runner=mock.Mock(), busy=lambda: None)
        self.assertEqual(report['status'], 'LIVE_DEFERRED')
        self.assertEqual(maintenance.archive_exit_code(report), 0)

    def test_remaining_queue_tracks_unattempted_pages_and_deduplicates_seed(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({"/a": (0, ""), "/b": (0, "")})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b"), self.plan("/a"), shadow=False,
            budget_sec=600, max_items=1, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(report["queue"], 2)
        self.assertEqual(report["remaining_queue"], 1)

    def test_missing_workspace_blocks_without_repeated_work(self):
        pg = self.FakePager()
        runner, _ = self.runner_for({"/missing": (2, "REFUSE_PAGE_WORKSPACE_NOT_FOUND")})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/missing"), [], shadow=False,
            budget_sec=600, max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(report["blocked"], 1)
        self.assertEqual(report["remaining_queue"], 0)

    def test_pressure_archive_largest_first_preserves_seed_and_blocks(self):
        pg = self.FakePager({'hostb|/blocked': {'reason': 'REFUSE_X'}})
        pg.pool_status = lambda: {'managed': {'eviction_active': True}}
        plan = self.plan('/small', '/large', '/blocked', '/seed')
        for row, size in zip(plan, (1, 100, 1000, 0)):
            row['size_bytes'] = size
        seeds = [dict(plan[-1], seed=True)]
        runner, calls = self.runner_for({p: (0, '') for p in ['/seed', '/large', '/small']})
        report = maintenance.archive_drain(self.cfg(), pg, plan, seeds, shadow=True,
            budget_sec=600, max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual([c[3] for c in calls], ['/seed', '/large', '/small'])
        self.assertEqual(report['order'], 'largest_first')
        self.assertEqual(report['blocked_candidates'], 1)
        self.assertTrue(all('--execute' not in c for c in calls))

    def test_folder_busy_refusal_stops_round_without_blocking(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({
            "/a": (2, "REFUSE_PAGE_ARCHIVE rc=2 detail=REFUSE_VAULT_WRITER_BUSY 123 python3 logical_vault_v3.py upload"),
            "/b": (0, ""),
        })
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b"), [], shadow=False, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(report["status"], "REFUSE_VAULT_WRITER_BUSY")
        self.assertEqual(pg.block_calls, [])
        self.assertEqual([c[3] for c in calls], ["/a"])

    def test_live_writer_precheck_waits_with_zero_attempts(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({"/a": (0, "")})
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a"), [], shadow=False, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: "999 vault_v2_stream.py", clock=lambda: 0.0)
        self.assertEqual(report["status"], "WAIT_VAULT_WRITER_BUSY")
        self.assertEqual(calls, [])
        self.assertEqual(report["attempts"], [])

    def test_budget_and_limit_bound_the_drain(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({k: (0, "") for k in ("/a", "/b", "/c")})
        ticks = iter([0.0, 0.0, 0.0, 100.0, 100.0, 100.0, 700.0, 700.0])
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b", "/c"), [], shadow=False, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: None, clock=lambda: next(ticks))
        self.assertEqual(report["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(report["archived"], 2)
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a", "/b", "/c"), [], shadow=False, budget_sec=600,
            max_items=1, runner=self.runner_for({k: (0, "") for k in ("/a", "/b", "/c")})[0],
            busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(report["status"], "LIMIT_REACHED")
        self.assertEqual(report["archived"], 1)

    def test_seeds_go_first_with_cold_days_zero_and_shadow_drops_execute(self):
        pg = self.FakePager()
        runner, calls = self.runner_for({"/seed": (0, ""), "/a": (0, "")})
        seeds = [{"path": "/seed", "workspace_key": "hostb|/seed", "seed": True}]
        report = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a"), seeds, shadow=True, budget_sec=600,
            max_items=10, runner=runner, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual([c[3] for c in calls], ["/seed", "/a"])
        self.assertEqual(calls[0][calls[0].index("--cold-days") + 1], "0")
        self.assertEqual(calls[1][calls[1].index("--cold-days") + 1], "15")
        self.assertNotIn("--execute", calls[0])
        self.assertEqual(report["mode"], "shadow")
        self.assertEqual(maintenance.last_archive_attempt(report)["workspace_key"], "hostb|/a")

    def test_idle_and_disabled_statuses(self):
        pg = self.FakePager()
        empty = maintenance.archive_drain(
            self.cfg(), pg, [], [], shadow=False, budget_sec=600, max_items=10,
            runner=lambda *a: None, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(empty["status"], "IDLE")
        off = maintenance.archive_drain(
            self.cfg(), pg, self.plan("/a"), [], shadow=False, budget_sec=600, max_items=0,
            runner=lambda *a: None, busy=lambda: None, clock=lambda: 0.0)
        self.assertEqual(off["status"], "DISABLED")

    def test_archive_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "archive.lock"
            with maintenance.archive_lock(lock) as first:
                self.assertTrue(first)
                with maintenance.archive_lock(lock) as second:
                    self.assertFalse(second)
            with maintenance.archive_lock(lock) as again:
                self.assertTrue(again)

    def test_archive_budget_rejects_bad_values(self):
        self.assertEqual(maintenance.archive_budget({}, "archive_budget_sec", 5400), 5400)
        self.assertEqual(maintenance.archive_budget({"archive_budget_sec": 60}, "archive_budget_sec", 5400), 60)
        for bad in (-1, "60", True, None):
            with self.assertRaises(RuntimeError):
                maintenance.archive_budget({"archive_budget_sec": bad}, "archive_budget_sec", 5400)


class ArchiveStageTests(unittest.TestCase):
    """archive_stage(): lock -> Baidu watcher gate -> drain."""

    class Proc:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lock = Path(self.tmp.name) / "archive.lock"
        self._orig_lock = maintenance.ARCHIVE_LOCK
        maintenance.ARCHIVE_LOCK = self.lock
        self._orig_flag = maintenance.PAGER_PRIORITY_FLAG
        maintenance.PAGER_PRIORITY_FLAG = Path(self.tmp.name) / ".pager_priority"
        self.cfg = {"archive_mode": "copy", "cold_days": 15, "archive_timeout_sec": 60,
                    "archive_block_days": 7, "max_archives_per_run": 4, "seed_paths": []}
        self.pg = ArchiveDrainTests.FakePager()
        self.plan = ArchiveDrainTests.plan("/a")

    def tearDown(self):
        maintenance.ARCHIVE_LOCK = self._orig_lock
        maintenance.PAGER_PRIORITY_FLAG = self._orig_flag
        self.tmp.cleanup()

    def test_dead_watcher_skips_drain(self):
        receipt = {}
        calls = []

        def runner(cmd, timeout):
            calls.append(cmd)
            return self.Proc(0, "")
        report = maintenance.archive_stage(
            self.cfg, self.pg, self.plan, receipt, shadow=False,
            budget_key="archive_tick_budget_sec", budget_default=1500, runner=runner,
            busy=lambda: None, watcher=lambda cfg, rc, runner: False)
        self.assertEqual(report["status"], "BAIDU_WATCHER_DEAD")
        self.assertEqual(calls, [])
        self.assertIsNone(receipt["archive"])

    def test_alive_watcher_drains(self):
        receipt = {}
        report = maintenance.archive_stage(
            self.cfg, self.pg, self.plan, receipt, shadow=False,
            budget_key="archive_tick_budget_sec", budget_default=1500,
            runner=lambda cmd, timeout: self.Proc(0, ""), busy=lambda: None,
            watcher=lambda cfg, rc, runner: True)
        self.assertEqual(report["status"], "DRAINED")
        self.assertEqual(report["archived"], 1)
        self.assertEqual(receipt["archive"]["workspace_key"], "hostb|/a")

    def test_empty_queue_never_stages_a_probe(self):
        probe = mock.Mock(side_effect=AssertionError("empty queue must not upload probes"))
        runner = mock.Mock(side_effect=AssertionError("empty queue must not run archives"))
        report = maintenance.archive_stage(
            self.cfg, self.pg, [], {}, shadow=False,
            budget_key="archive_tick_budget_sec", budget_default=1500,
            runner=runner, busy=lambda: None, watcher=probe)
        self.assertEqual(report["status"], "IDLE")
        probe.assert_not_called()

    def test_active_writer_prevents_probe_side_effects(self):
        probe = mock.Mock(side_effect=AssertionError("writer owns staging folder"))
        report = maintenance.archive_stage(
            self.cfg, self.pg, self.plan, {}, shadow=False,
            budget_key="archive_tick_budget_sec", budget_default=1500,
            busy=lambda: 'real writer', watcher=probe)
        self.assertEqual(report["status"], "WAIT_VAULT_WRITER_BUSY")
        probe.assert_not_called()

    def test_failed_work_cannot_be_reported_as_successful_cron(self):
        for status in ('RETRY_PENDING', 'BAIDU_WATCHER_DEAD', 'ARCHIVE_TIMEOUT'):
            self.assertEqual(maintenance.archive_exit_code({'status': status}), 2)
        self.assertEqual(maintenance.archive_exit_code({'status': 'LIMIT_REACHED', 'retry_queue': 1}), 2)
        self.assertEqual(maintenance.archive_exit_code({'status': 'IDLE'}), 0)

    def test_shadow_mode_skips_watcher_gate(self):
        seen = []
        report = maintenance.archive_stage(
            self.cfg, self.pg, self.plan, {}, shadow=True,
            budget_key="archive_tick_budget_sec", budget_default=1500,
            runner=lambda cmd, timeout: self.Proc(0, ""), busy=lambda: None,
            watcher=lambda cfg, rc, runner: seen.append(1) or False)
        self.assertEqual(seen, [])
        self.assertEqual(report["status"], "DRAINED")

    def test_lock_held_elsewhere_waits(self):
        with maintenance.archive_lock(self.lock) as held:
            self.assertTrue(held)
            report = maintenance.archive_stage(
                self.cfg, self.pg, self.plan, {}, shadow=False,
                budget_key="archive_tick_budget_sec", budget_default=1500,
                runner=lambda cmd, timeout: self.Proc(0, ""), busy=lambda: None,
                watcher=lambda cfg, rc, runner: True)
        self.assertEqual(report["status"], "WAIT_ARCHIVE_LOCK")

    def test_ensure_baidu_watcher_parses_tool_json(self):
        receipt = {}
        ok = maintenance.ensure_baidu_watcher(
            {"watcher_probe_timeout_sec": 5}, receipt,
            runner=lambda cmd, timeout: self.Proc(0, 'noise\n{"verdict": "WATCHER_ALIVE"}\n'))
        self.assertTrue(ok)
        self.assertEqual(receipt["baidu_watcher"]["verdict"], "WATCHER_ALIVE")
        bad = maintenance.ensure_baidu_watcher(
            {}, receipt, runner=lambda cmd, timeout: self.Proc(3, '{"verdict": "WATCHER_DEAD"}'))
        self.assertFalse(bad)
        garbage = maintenance.ensure_baidu_watcher(
            {}, receipt, runner=lambda cmd, timeout: self.Proc(1, ""))
        self.assertFalse(garbage)
        self.assertEqual(receipt["baidu_watcher"]["verdict"], "WATCHER_PROBE_UNPARSEABLE")


class PagerPriorityTests(unittest.TestCase):
    """<date>: the v3 migration uploader yields the Baidu writer to the pager."""

    def _pager(self, active):
        pg = mock.Mock()
        pg.pool_status.return_value = {"managed": {"eviction_active": active, "free_ratio": 0.067 if active else 0.2}}
        return pg

    def test_flag_set_under_pressure_and_when_archive_queue_nonempty(self):
        with tempfile.TemporaryDirectory() as td:
            flag = Path(td) / ".pager_priority"
            out = maintenance.publish_pager_priority(self._pager(True), {"queue": 0}, flag=flag)
            self.assertTrue(out["active"] and flag.is_file())
            self.assertIn('"eviction_active": true', flag.read_text())
            flag.unlink()
            out = maintenance.publish_pager_priority(self._pager(False), {"queue": 3}, flag=flag)
            self.assertTrue(out["active"] and flag.is_file())
            self.assertIn('"archive_queue": 3', flag.read_text())

    def test_flag_cleared_only_by_a_tick_allowed_to_clear(self):
        with tempfile.TemporaryDirectory() as td:
            flag = Path(td) / ".pager_priority"
            flag.write_text("{}")
            out = maintenance.publish_pager_priority(self._pager(False), None, flag=flag, allow_clear=False)
            self.assertFalse(out["active"])
            self.assertTrue(flag.is_file())
            out = maintenance.publish_pager_priority(self._pager(False), {"queue": 0}, flag=flag)
            self.assertTrue(out.get("cleared"))
            self.assertFalse(flag.exists())

    def test_drained_initial_queue_does_not_starve_migration(self):
        with tempfile.TemporaryDirectory() as td:
            flag = Path(td) / ".pager_priority"
            flag.write_text("old priority")
            out = maintenance.publish_pager_priority(
                self._pager(False), {"queue": 24, "remaining_queue": 0,
                                     "retry_queue": 22}, flag=flag)
            self.assertFalse(out["active"])
            self.assertFalse(flag.exists())
            out = maintenance.publish_pager_priority(
                self._pager(True), {"queue": 24, "remaining_queue": 0}, flag=flag)
            self.assertTrue(out["active"])

    def test_archive_stage_publishes_after_a_real_drain(self):
        import inspect
        source = inspect.getsource(maintenance.archive_stage)
        self.assertIn('if "queue" in receipt["archive_drain"]:', source)
        self.assertIn("publish_pager_priority(pg, receipt[\"archive_drain\"])", source)
        self.assertIn("allow_clear=False", inspect.getsource(maintenance.main))


class EvictionBlockReconciliationTests(unittest.TestCase):
    def pager(self):
        rows = {
            'old': {'reason': 'REFUSE_INITIAL_RESTORE_PROOF_MISSING run --verify-initial-only first', 'at': 1},
            'path': {'reason': 'NO_ELIGIBLE_CONFIRMED_hostb_ASSET', 'at': 1},
            'changed': {'reason': 'REFUSE_LOCAL_CHANGED_REARCHIVE_REQUIRED', 'at': 1},
            'busy': {'reason': 'REFUSE_SOURCE_HAS_OPEN_HANDLES', 'at': 1},
        }
        class Pager:
            def eviction_blocks(self):
                return {key: dict(value) for key, value in rows.items()}
            def unblock_eviction(self, asset, *, expected=None):
                if rows.get(asset) != expected:
                    return False
                del rows[asset]
                return True
        return Pager(), rows

    def test_retired_gate_retries_only_after_current_admission(self):
        pg, rows = self.pager()
        def admit(asset):
            if asset == 'path':
                raise SystemExit('NO_ELIGIBLE_CONFIRMED_hostb_ASSET')
            return {'asset_id': asset}
        result = maintenance.reconcile_eviction_blocks(pg, admit=admit)
        self.assertEqual(result['released'], ['old'])
        self.assertEqual(set(rows), {'path', 'changed', 'busy'})

    def test_changed_refusal_during_probe_survives(self):
        pg, rows = self.pager()
        def admit(asset):
            rows[asset] = {'reason': 'REFUSE_SOURCE_HAS_OPEN_HANDLES', 'at': 2}
            return {'asset_id': asset}
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], [])
        self.assertIn('old', rows)

    def test_wrong_asset_and_unreadable_authority_fail_closed(self):
        pg, rows = self.pager()
        def admit(asset):
            if asset == 'old':
                return {'asset_id': 'different'}
            raise OSError('catalog unavailable')
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], [])
        self.assertEqual(len(rows), 4)

    def test_drift_retries_only_after_new_confirmed_snapshot_and_admission(self):
        from types import SimpleNamespace
        block = {'reason': 'REFUSE_LOCAL_CHANGED_REARCHIVE_REQUIRED asset=a', 'at': 100}
        row = {'cloud_asset_id': 'a', 'cloud_verified': 1, 'snapshot_verified': 1,
               'dirty': 0, 'archive_epoch': 99}
        cleared = []
        pg = SimpleNamespace(eviction_blocks=lambda: {'a': dict(block)},
            status=lambda asset: {'rows': [dict(row)]},
            unblock_eviction=lambda asset, expected: cleared.append(asset) or True)
        admit = lambda asset: {'asset_id': asset}
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], [])
        row['archive_epoch'] = 101
        for field in ('cloud_verified', 'snapshot_verified'):
            row[field] = 0
            self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], [])
            row[field] = 1
        row['dirty'] = 1
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], [])
        row['dirty'] = 0
        def denied(asset):
            raise SystemExit('NO_ELIGIBLE_CONFIRMED_hostb_ASSET')
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=denied)['released'], [])
        self.assertEqual(maintenance.reconcile_eviction_blocks(pg, admit=admit)['released'], ['a'])
        self.assertEqual(cleared, ['a'])


if __name__ == "__main__":
    unittest.main()
