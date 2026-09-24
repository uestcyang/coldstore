#!/usr/bin/env python3
"""Fail-closed PAI page preflight with a bounded zero-work fast path."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MAC_WS = "/Users/user/.coldstore/bin/ws"
MAC_SSH = "user@host-a"
NODE_hostb = "user@host-b"
CATALOGS = [
    Path("/Users/user/.coldstore/archive/cloud_asset_catalog.jsonl"),
    Path("/home/user/.coldstore/archive/cloud_asset_catalog.jsonl"),
]


HOME_BY_HOST = {"mac": "/Users/user", "hostb": "/home/user"}
# 路径右边界:除空白/引号/括号外必须放行 "/",因为 skill/任务书里的写法是
# `~/engine-a/`、`~/engine-c/sub` 这种带尾斜杠或指向目录内文件的形式。
PATH_RIGHT_BOUNDARY = r"(?=$|[/\s'\"`),;\]}])"
# 子路径引用 = 资产目录内的具体文件,说明任务真要读内容。它是豁免声明的
# 唯一否决条件,不能只靠"任务自称是维护单"。
CHILD_REF = r"/[^\s'\"`),;\]}]"

# 显式豁免(<date>):真实事故——"删 hostb-wan-vace 暂存残骸"的清理单
# 因提到资产名被要求先拉回 19.4GB。闸把"提及"当"使用",维护单被自己锁死。
# 语法:  PAGE_GATE_NO_READ: <asset_id> reason=<理由>
# 防滥用三条:asset_id 必须真实存在;理由必须够长;任务书一旦引用该资产的
# 子路径,声明立即失效(见 CHILD_REF)。
DECLARATION_RE = re.compile(
    r"^[ \t>*-]*PAGE_GATE_NO_READ[ \t]*:[ \t]*(?P<asset>[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"(?P<rest>[^\n]*)$", re.MULTILINE)
REASON_RE = re.compile(r"reason[ \t]*=[ \t]*(?P<reason>[^\n]*?)[ \t]*$")
MIN_REASON_LEN = 8

# restore 失败前会先打印几十行 NEED 清单(正常输出),原实现取尾部 3000 字符
# 会把真正的 REFUSE_* 挤出窗口,首行还被拦腰截断成乱码。
NOISE_PREFIX = "NEED "
SIGNAL_RE = re.compile(r"^\s*(REFUSE_[A-Z0-9_]+|ERROR\b|Traceback\b|\w*Error:)")


class GateRefused(RuntimeError):
    pass


def asset_host(asset):
    return "mac" if str(asset.get("machine", "")).casefold() == "mac" else "hostb"


def path_aliases(original, host):
    """一个资产的等价书写形式。

    catalog 只存绝对路径(/home/user/engine-a),但 skill 与任务书通篇用
    `~/engine-a`。不归一化,gate 对自己产线的标准写法会静默 fail-open。
    """
    base = str(original or "").rstrip("/")
    if not base:
        return []
    out = [base]
    home = HOME_BY_HOST.get(host)
    if home and base.startswith(home + "/"):
        out.append("~/" + base[len(home) + 1:])
    return out


def load_assets():
    path = next((p for p in CATALOGS if p.is_file()), None)
    if path is None:
        raise GateRefused("REFUSE_PAGE_CATALOG_MISSING")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def requirements(text, assets):
    out = []
    for asset in assets:
        asset_id = str(asset.get("asset_id") or "")
        original = str(asset.get("original_path") or "")
        host = asset_host(asset)
        asset_hit = bool(asset_id and re.search(
            r"(?<![A-Za-z0-9_-])" + re.escape(asset_id) + r"(?![A-Za-z0-9_-])", text
        ))
        aliases = path_aliases(original, host)
        path_hit = any(
            re.search(re.escape(alias) + PATH_RIGHT_BOUNDARY, text) for alias in aliases
        )
        # 引用目录内的具体文件 => 真要读内容,任何豁免声明都不得放行
        child_ref = any(
            re.search(re.escape(alias) + CHILD_REF, text) for alias in aliases
        )
        if asset_hit or path_hit:
            out.append({
                "asset_id": asset_id,
                "host": host,
                "original_path": original,
                "cloud_verified": asset.get("cloud_state") == "confirmed",
                "child_ref": child_ref,
            })
    return out


def declarations(text):
    """解析任务书里的显式豁免声明,返回 {asset_id: reason}。

    理由过短/缺失一律 fail-closed:写了声明却说不出理由,等于没有可审计依据。
    """
    out = {}
    for m in DECLARATION_RE.finditer(text or ""):
        asset_id = m.group("asset")
        rm = REASON_RE.search(m.group("rest") or "")
        reason = (rm.group("reason").strip() if rm else "")
        if len(reason) < MIN_REASON_LEN:
            raise GateRefused(
                f"REFUSE_PAGE_DECLARATION_REASON_TOO_SHORT asset={asset_id} "
                f"reason={reason!r} min_len={MIN_REASON_LEN}")
        out[asset_id] = reason
    return out


def apply_declarations(needs, decls, assets):
    """就地给命中项打豁免;返回被否决的声明数。

    否决而非静默忽略:声明生效与否必须在回执里留痕,否则下一个人无法判断
    这单到底跳过了什么。
    """
    known = {str(a.get("asset_id") or "") for a in assets}
    for asset_id in decls:
        if asset_id not in known:
            # 拼错 asset_id 会让人误以为已豁免,而闸照旧拦——必须当场炸
            raise GateRefused(
                f"REFUSE_PAGE_DECLARATION_UNKNOWN_ASSET asset={asset_id}")
    overridden = 0
    for item in needs:
        reason = decls.get(item["asset_id"])
        if not reason:
            continue
        if item.get("child_ref"):
            item["declaration_overridden"] = True
            item["declaration_reason"] = reason
            overridden += 1
            continue
        item["verdict"] = "PAGE_SKIP_DECLARED"
        item["skip_reason"] = reason
    return overridden


def summarize_failure(stdout, stderr, returncode, limit=1200):
    """把 restore 的刷屏输出压成可诊断摘要。

    NEED 清单是正常输出(一个资产几十行),不折叠就会把真正的 REFUSE_* 挤出
    尾部窗口,等于 fail-closed 了却给不出原因。
    """
    lines = [ln.rstrip() for ln in (str(stdout or "") + "\n" + str(stderr or "")).splitlines()]
    noise = sum(1 for ln in lines if ln.startswith(NOISE_PREFIX))
    signal = [ln for ln in lines if ln.strip() and not ln.startswith(NOISE_PREFIX)]
    keep = [ln for ln in signal if SIGNAL_RE.match(ln)] or signal
    body = " | ".join(keep[-6:])[-limit:]
    if noise:
        body = f"[folded {noise} NEED lines] {body}"
    return f"rc={returncode} {body}".strip()


def path_exists(host, path):
    on_mac = platform.system() == "Darwin"
    if (on_mac and host == "mac") or (not on_mac and host == "hostb"):
        return os.path.exists(path)
    target = NODE_hostb if host == "hostb" else MAC_SSH
    return subprocess.run(["ssh", "-n", target, "test", "-e", path],
                          stdin=subprocess.DEVNULL).returncode == 0


def page_in(asset_id, timeout):
    if platform.system() == "Darwin":
        cmd = [MAC_WS, "page", "enter", "--asset-id", asset_id,
               "--timeout", str(timeout)]
    else:
        cmd = ["ssh", "-n", MAC_SSH, MAC_WS, "page", "enter",
               "--asset-id", asset_id, "--timeout", str(timeout)]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 60)
    if proc.returncode:
        raise GateRefused(
            f"REFUSE_PAGE_IN asset={asset_id} "
            + summarize_failure(proc.stdout, proc.stderr, proc.returncode))
    return proc.stdout.strip()


def write_receipt(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, target)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--timeout", type=float, default=24 * 3600)
    args = ap.parse_args()
    prompt = Path(args.prompt)
    if not prompt.is_file() or prompt.stat().st_size > 5 * 1024 * 1024:
        raise GateRefused(f"REFUSE_PAGE_PROMPT_INVALID {prompt}")
    text = prompt.read_text(encoding="utf-8", errors="replace")
    assets = load_assets()
    needs = requirements(text, assets)
    decls = declarations(text)
    overridden = apply_declarations(needs, decls, assets)
    for item in needs:
        if item.get("verdict") == "PAGE_SKIP_DECLARED":
            continue
        if path_exists(item["host"], item["original_path"]):
            item["verdict"] = "PAGE_HIT"
            continue
        if not item["cloud_verified"]:
            raise GateRefused(f"REFUSE_REQUIRED_ASSET_NOT_LOCAL_OR_CLOUD {item['asset_id']}")
        item["page_in"] = page_in(item["asset_id"], args.timeout)
        if not path_exists(item["host"], item["original_path"]):
            raise GateRefused(f"REFUSE_PAGE_IN_NOT_MATERIALIZED {item['asset_id']}")
        item["verdict"] = "PAGE_IN_PASS"
    payload = {"schema_version": 2, "requirements": needs,
               "declarations": decls, "declarations_overridden": overridden,
               "verdict": "PAGE_GATE_PASS"}
    write_receipt(args.receipt, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateRefused as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
