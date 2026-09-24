#!/usr/bin/env python3
import unittest
import workspace_page_gate as gate


class WorkspacePageGateTests(unittest.TestCase):
    def test_matches_only_explicit_asset_or_original_path(self):
        assets = [{"asset_id": "asset-a", "original_path": "/x/a",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        self.assertEqual(gate.requirements("unrelated", assets), [])
        self.assertEqual(gate.requirements("use asset-a", assets)[0]["host"], "hostb")
        self.assertEqual(gate.requirements("read /x/a", assets)[0]["asset_id"], "asset-a")

    def test_pending_state_is_not_cloud_verified(self):
        assets = [{"asset_id": "a", "original_path": "/x",
                   "machine": "Mac", "cloud_state": "pending"}]
        self.assertFalse(gate.requirements("a", assets)[0]["cloud_verified"])

    def test_parent_path_prefix_does_not_false_match(self):
        assets = [{"asset_id": "parent", "original_path": "/data/video",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        self.assertEqual(gate.requirements("read /data/video_full/output", assets), [])

    def test_asset_id_prefix_does_not_false_match(self):
        assets = [{"asset_id": "tool", "original_path": "/data/tool",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        self.assertEqual(gate.requirements("use tool-new", assets), [])

    # --- 波浪号归一化(<date>):skill/任务书通篇写 ~/engine-a,
    # catalog 只存 /home/user/engine-a。不归一化 gate 对自己产线的
    # 标准写法静默 fail-open,已实测 7 个真实场景中 5 个被放行。
    def _engine(self):
        return [{"asset_id": "hostb-wan-vace", "original_path": "/home/user/engine-a",
                 "machine": "hostb", "cloud_state": "confirmed"}]

    def test_tilde_form_is_matched_for_hostb_asset(self):
        hit = gate.requirements("在 hostb `~/engine-a/` 跑五步管线", self._engine())
        self.assertEqual([h["asset_id"] for h in hit], ["hostb-wan-vace"])

    def test_tilde_form_with_ssh_prefix_is_matched(self):
        hit = gate.requirements("在 user@host-b:~/engine-a/ 跑", self._engine())
        self.assertEqual([h["asset_id"] for h in hit], ["hostb-wan-vace"])

    def test_tilde_form_is_matched_for_mac_asset(self):
        assets = [{"asset_id": "mac-file-001",
                   "original_path": "/Users/user/engine-e/checkpoints/gpt.pth",
                   "machine": "Mac", "cloud_state": "confirmed"}]
        hit = gate.requirements("用 ~/engine-e/checkpoints/gpt.pth 起 tts-engine", assets)
        self.assertEqual([h["asset_id"] for h in hit], ["mac-file-001"])

    def test_trailing_slash_and_child_path_are_matched(self):
        # `~/engine-c/sub` 指向被淘汰目录内的文件,同样必须触发 page-in
        assets = [{"asset_id": "hostb-engine-c", "original_path": "/home/user/engine-c",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        for text in ("engine-c-sub 在 `~/engine-c/sub`",
                     "cd /home/user/engine-c/sub && python inference.py"):
            with self.subTest(text=text):
                self.assertEqual(
                    [h["asset_id"] for h in gate.requirements(text, assets)],
                    ["hostb-engine-c"])

    def test_tilde_does_not_cross_hosts(self):
        # hostb 资产的 ~ 形式不得由 Mac home 前缀推出,避免跨机误触发下载
        assets = [{"asset_id": "hostb-only", "original_path": "/home/user/engine-a",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        self.assertEqual(
            gate.path_aliases("/home/user/engine-a", "mac"),
            ["/home/user/engine-a"])
        self.assertEqual(
            [h["asset_id"] for h in gate.requirements("/Users/user/engine-a", assets)],
            [])

    def test_tilde_still_rejects_sibling_prefix(self):
        assets = [{"asset_id": "p", "original_path": "/home/user/video",
                   "machine": "hostb", "cloud_state": "confirmed"}]
        self.assertEqual(gate.requirements("读 ~/video_full/out", assets), [])

    def test_non_home_path_has_no_tilde_alias(self):
        self.assertEqual(gate.path_aliases("/data/comfyui", "hostb"), ["/data/comfyui"])

    # --- 提及≠使用(<date>):真实事故——一张"删 hostb-wan-vace 暂存残骸"
    # 的清理单,因任务书里写了资产名被判 REFUSE_PAGE_IN,要求先把 19.4GB
    # 拉回来才准跑。闸把"提到"当成"要读",维护类任务被自己的闸锁死。
    def test_root_reference_is_not_marked_child(self):
        for text in ("清理 hostb-wan-vace 残骸", "看 ~/engine-a 目录", "ls ~/engine-a/"):
            with self.subTest(text=text):
                hit = gate.requirements(text, self._engine())
                self.assertEqual(len(hit), 1)
                self.assertFalse(hit[0]["child_ref"], "根引用不该标 child_ref")

    def test_child_path_reference_is_marked_child(self):
        hit = gate.requirements("跑 ~/engine-a/scripts/gen.py", self._engine())
        self.assertTrue(hit[0]["child_ref"], "引用目录内文件必须标 child_ref")

    def test_declaration_parsed_with_reason(self):
        got = gate.declarations(
            "PAGE_GATE_NO_READ: hostb-wan-vace reason=只删staging残骸不读内容")
        self.assertIn("hostb-wan-vace", got)
        self.assertIn("staging", got["hostb-wan-vace"])

    def test_declaration_requires_nonempty_reason(self):
        for bad in ("PAGE_GATE_NO_READ: hostb-wan-vace",
                    "PAGE_GATE_NO_READ: hostb-wan-vace reason=",
                    "PAGE_GATE_NO_READ: hostb-wan-vace reason=x"):
            with self.subTest(bad=bad):
                with self.assertRaises(gate.GateRefused):
                    gate.declarations(bad)

    def test_declaration_ignores_unrelated_text(self):
        self.assertEqual(gate.declarations("普通任务书,没有声明"), {})

    def test_resolve_skips_declared_root_only_reference(self):
        needs = gate.requirements("清理 hostb-wan-vace 残骸", self._engine())
        decls = {"hostb-wan-vace": "只删 staging 残骸,不读资产内容"}
        gate.apply_declarations(needs, decls, self._engine())
        self.assertEqual(needs[0]["verdict"], "PAGE_SKIP_DECLARED")
        self.assertIn("staging", needs[0]["skip_reason"])

    def test_declaration_cannot_skip_child_path_reference(self):
        # 防滥用主闸:声明了却仍引用目录内文件,说明真要读内容,声明无效
        needs = gate.requirements("PAGE_GATE_NO_READ: hostb-wan-vace reason=只是清理\n"
                                  "然后跑 ~/engine-a/scripts/gen.py", self._engine())
        decls = {"hostb-wan-vace": "只是清理"}
        gate.apply_declarations(needs, decls, self._engine())
        self.assertNotIn("verdict", needs[0])
        self.assertTrue(needs[0]["declaration_overridden"])

    def test_declaration_for_unknown_asset_is_refused(self):
        # 拼错 asset_id 会让人以为已豁免,实际闸照旧拦——必须当场报错
        with self.assertRaises(gate.GateRefused):
            gate.apply_declarations([], {"no-such-asset": "理由够长的说明"},
                                    self._engine())

    # --- 诊断可读性(<date>):restore 失败时先打印几十行 NEED 清单,
    # 再报 REFUSE_*。原实现取 stdout+stderr 尾部 3000 字符,真因被 blob
    # 清单挤出窗口,首行还被拦腰截断成乱码。
    def test_summarize_keeps_refusal_line(self):
        noise = "\n".join(f"NEED /x/{i}.blob sha256=deadbeef bytes=1000000" for i in range(60))
        out = gate.summarize_failure(noise, "REFUSE_RESTORE_ALREADY_RUNNING asset=a", 2)
        self.assertIn("REFUSE_RESTORE_ALREADY_RUNNING", out)
        self.assertIn("rc=2", out)

    def test_summarize_folds_need_lines_into_count(self):
        noise = "\n".join(f"NEED /x/{i}.blob" for i in range(60))
        out = gate.summarize_failure(noise, "REFUSE_X", 2)
        self.assertNotIn("/x/59.blob", out)
        self.assertIn("60", out)

    def test_summarize_falls_back_when_no_signal_line(self):
        out = gate.summarize_failure("", "totally unexpected blob", 7)
        self.assertIn("unexpected", out)
        self.assertIn("rc=7", out)


if __name__ == "__main__":
    unittest.main()
