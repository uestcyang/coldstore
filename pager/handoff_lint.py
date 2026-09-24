#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""handoff_lint.py — 工作区接手通稿(HANDOFF.md)覆盖率 + 规范符合度硬闸

规范本体:skill `workspace-handoff`(<date> operator-defined)
建立:<date> A线全量体检(权限链 用户-agent-c,用户QQ指令"全量体检补建HANDOFF")

做两件事:
  1) 覆盖率:扫候选工作区,报哪些"够格叫多 agent 工作区"却没有 HANDOFF.md
  2) 符合度:对已有的 HANDOFF.md 逐份查四大块 / 权限链格式 / ⭐验收标记 / 当前态是否过期

硬约束(用户 <date> 令):
  - 零外网请求。全程只读本机文件系统 + 本地 dispatch 记录。
    (<date> --push 例外:仅局域网 the LAN 内的 notify_push,不出公网)
  - 不提频:设计为 crontab 每日一次。脚本自身不含任何轮询/sleep 循环。
  - 只读:本脚本从不写入被扫目录,只写自己的 log 与 ~/.coldstore/state 挂单状态。

判据(为什么这么定,见 --explain):
  「够格」= 满足以下任一:
    A. 在 ~/.coldstore/dispatch/{done,failed}/*/prompt.md 里被 >= 2 个不同派单引用过
    B. 目录内文件 mtime 跨度 > 3 天 且 文件数 >= MIN_FILES
       且 被第二来源引用过(skill / 已有 HANDOFF.md / ~/.coldstore/notes 提到它)
  单靠 mtime 跨度不算数 —— 否则 ~/Downloads、~/.ssh、miniconda3 全会被误判成工作区。
  排除:/tmp、node_modules/.git/缓存/venv、模型权重、系统/工具目录(DENY_NAMES)、纯空壳

退出码:0=全绿 / 1=有 P0 缺失或不合规 / 2=仅 P1P2 告警 / 3=脚本自身取证失败
"""

import argparse
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timedelta

HOME = os.path.expanduser("~")
DISPATCH = os.path.join(HOME, ".coldstore", "dispatch")
LOGDIR = os.path.join(HOME, ".coldstore", "logs")
LOGFILE = os.path.join(LOGDIR, "handoff_lint.log")

# ---- 告警(<date> operator directive加) ----
# 病根:本脚本原本是**哑巴闸**——查出 P0 缺失只写本地日志,退出码 1 没人看,
# 于是 示例项目/初高衔接班 的 P0 连挂 3 轮(3天)无人修,工作区闸每天照拦,空转。
# 治法:带状态的挂单追踪 + 越挂越响。不是"每天推一遍"(那是刷屏,用户红线),
# 而是 新增/恶化 立刻推;老问题按 1→3→7 天退避复推,并把"已挂 N 轮"写进标题。
STATEDIR = os.path.join(HOME, ".coldstore", "state")
STATEFILE = os.path.join(STATEDIR, "handoff_lint_state.json")
PUSH_BIN = os.path.join(HOME, ".coldstore", "bin", "notify_push")
PUSH_ROLE = "agent-k"          # 用户手机当前会话通道
NAG_STEPS = [1, 3, 7]       # 老问题复推退避(天):挂越久间隔越长但绝不静默

MIN_FILES = 5           # 少于这个文件数的目录不算工作区(空壳/挂载点残留)
SPAN_DAYS = 3           # mtime 跨度门槛
STALE_DAYS = 14         # 「当前态」与目录最新产物差这么多天 => 疑似过期

EXCLUDE_PAT = re.compile(
    r"(^/tmp/|/node_modules/|/\.git/|/\.venv/|/venv/|/__pycache__/|/\.cache/"
    r"|/site-packages/|/\.next/|/build/|/dist/|/\.Trash/|/Library/|/\.npm/"
    r"|/checkpoints?/|/weights?/|/\.ollama/|/\.cargo/|/\.rustup/)"
)

# ---------- 快照副本区(<date> 实测新增) ----------
# 病根:整目录快照会连 HANDOFF.md 一起复制,深层补扫(find $HOME -name HANDOFF.md)
# 把每一份冻结副本都当成独立活工作区计数。Mac 实测 38 份 "ok" 里有 15 份是
# ~/app-a_backups/pre-*/ 的冻结副本 —— 真实活工作区只有 23 份。
# 危害不只是计数虚高:副本**天然永远合规**(它复制的是当时已合规的文件,且再也
# 不会变),会持续稀释真实合规率,把活工作区的问题按在小数点后面。
# 判据:任一**祖先**目录名以 backups/snapshots/snaps/baks 结尾 => 冻结副本。
# 备份区**父目录自己**仍算工作区(它是真的在被管理、要写通稿的实体)。
SNAPSHOT_DIR_RE = re.compile(
    r"(?:backups?|snapshots?|snaps?|baks?)$"
    r"|(?:^|[_-])backups_local$"
    r"|(?:^|[_-])(?:backup|snapshot|snap|bak)[_-]20\d{6}(?:[_-].*)?$",
    re.I,
)

# 完工科学审计会把整套产物(含 HANDOFF.md)锁成 0444，并在 STATUS*.json /
# ARTIFACT_LOCK.json 留终态回执。此时它已经是不可变证据包，不再是可继续维护的活
# 工作区；强行按最新通稿模板修它，反而会破坏冻结哈希。只读本身不够，必须同时
# 命中机器可读终态字段，避免把权限误配或未完工的只读目录静默排除。
TERMINAL_RECEIPT_FILES = (
    "STATUS.json", "STATUS_RECEIPT.json", "ARTIFACT_LOCK.json",
)
TERMINAL_RECEIPT_KEYS = (
    "status", "terminal_status", "audit_status", "contract_result",
)
TERMINAL_RECEIPT_RE = re.compile(
    r"^(?:complete(?:d)?(?:[_ -].*)?|done|closed|final(?:ized)?|pass(?:ed)?)$",
    re.I,
)


def is_frozen_terminal_artifact(path):
    """是否为有机器回执证明的 0444 终态证据包。"""
    path = os.path.normpath(path)
    hp = os.path.join(path, "HANDOFF.md")
    try:
        if not os.path.isfile(hp) or (os.stat(hp).st_mode & 0o222):
            return False
    except OSError:
        return False

    # 顶层任一普通文件仍可写，说明目录仍可能在推进，不得因旧回执误排除。
    try:
        for name in os.listdir(path):
            fp = os.path.join(path, name)
            if os.path.isfile(fp) and not os.path.islink(fp):
                if os.stat(fp).st_mode & 0o222:
                    return False
    except OSError:
        return False

    for name in TERMINAL_RECEIPT_FILES:
        fp = os.path.join(path, name)
        try:
            with open(fp, encoding="utf-8", errors="ignore") as f:
                payload = json.load(f)
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in TERMINAL_RECEIPT_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and TERMINAL_RECEIPT_RE.fullmatch(value.strip()):
                return True
    return False


def is_snapshot_copy(path):
    """path 是否为快照区内部副本或有回执的只读终态证据包。"""
    if is_frozen_terminal_artifact(path):
        return True
    parent = os.path.dirname(os.path.normpath(path))
    while parent and parent != "/" and parent != HOME:
        if SNAPSHOT_DIR_RE.search(os.path.basename(parent)):
            return True
        parent = os.path.dirname(parent)
    return False


# ~/.coldstore 根工作区内部的实现/运行态子树：实体和历史 HANDOFF 保留，但它们的
# 生命周期、权限链和接手责任都归根区，不应重复计成独立工作区。
NON_WORKSPACE_REL_ROOTS = (
    os.path.join(".coldstore", ".claude", "worktrees"),
    os.path.join(".coldstore", "logs"),
    os.path.join(".coldstore", "state"),
    os.path.join(".coldstore", "scripts"),
    os.path.join(".coldstore", "skill_router_replay"),
    os.path.join(".coldstore", "dispatch", "results"),
    os.path.join(".coldstore", "archive"),
    os.path.join(".coldstore", "tmp"),
    # 独立生命周期不成立的 profile/共享运行环境：实体仍保留并被服务引用，
    # 但治理责任归 ~/.coldstore 根区或当前角色区，不应被当成新的协作工作区。
    ".agent-agent-g",
    ".agent-agent-e",
    ".agent-shared",
    # ~/.coldstore 根区内部的配置叶子同理。
    os.path.join(".coldstore", "etc"),
    # 顶层依赖环境、用户级命令目录和已冻结的一次性旧产物。
    ".npm-global",
    "bin",
    "snap",
    "agent-g-sub",
    "engine-a/engine-a-core",
    "research-runtime",
    "task-dir-a",
    "示例配音目录",
    # Mac 侧 Codex/Hermes 自身运行态、退役收纳与技能镜像，均由机制根治理。
    ".codex",
    os.path.join(".coldstore", "_deleted"),
    os.path.join(".coldstore", "cron"),
    os.path.join(".coldstore", "plugins"),
    os.path.join(".coldstore", "profiles"),
    os.path.join(".coldstore", "skills"),
    os.path.join(".coldstore", "tasks"),
    "skills-core-baks",
)

# 这两个顶层只是多项目/成品容器；其下带 HANDOFF 的真实子工作区必须继续索引，
# 因此只能排除**根本身**，不能像 NON_WORKSPACE_REL_ROOTS 那样整棵剪枝。
NON_WORKSPACE_EXACT_REL_ROOTS = ("agent-j", "agent-h")


def is_nonworkspace_path(path, home=None):
    """Return True only for known implementation/runtime subtrees; pure/testable."""
    home = os.path.normpath(home or HOME)
    path = os.path.normpath(path)
    roots = tuple(os.path.join(home, rel) for rel in NON_WORKSPACE_REL_ROOTS)
    exact = tuple(os.path.join(home, rel) for rel in NON_WORKSPACE_EXACT_REL_ROOTS)
    rel_parts = os.path.relpath(path, home).split(os.sep)
    venv_like = any(
        part == "venv" or part.startswith(".venv")
        or part.endswith(("-venv", "_venv"))
        for part in rel_parts
    )
    return (venv_like or path in exact
            or any(path == root or path.startswith(root + os.sep) for root in roots))


# 系统/工具/下载类目录:再怎么改也不是"多 agent 协作工作区",直接不看
DENY_NAMES = {
    "Downloads", "Movies", "Music", "Pictures", "Documents", "Applications",
    "Library", "Public", "Desktop", "miniconda3", "anaconda3", "go", "sdk",
    ".ssh", ".config", ".local", ".docker", ".android", ".vscode", ".cache",
    ".cursor", ".trae-cn", ".cline", ".zsh_sessions", ".npm", ".Trash",
    ".browser-profile-a", ".kimi", ".kimi_openclaw", ".openclaw", ".local-llm",
    ".agents", ".claude", ".coldstore", "d2l-zh", "engine-c", "engine-e",
    "cloudbase-framework", "miniforge3", "Movies", "同步盘",
    ".gradle", "agent", "skills-core-migration-backup",
}

# 候选根:在这些目录下面找工作区(maxdepth 见 SCAN_DEPTH)
SCAN_ROOTS = [
    (HOME, 1),
    (os.path.join(HOME, "Desktop", "示例项目"), 1),
    (os.path.join(HOME, ".coldstore"), 1),
    (os.path.join(HOME, "示例项目"), 1),
    (os.path.join(HOME, "agent-j"), 1),
    (os.path.join(HOME, "trae_projects"), 1),
]

# P0 = 核心产线/派单总线,缺 HANDOFF 直接 exit 1
P0_MARKERS = [
    ".coldstore/dispatch", ".coldstore/notes", "app-a", "app-demo",
    "agent_roles", "app-a_backups", "agent-j/research",
    "skills-core", "agent-hardened-scripts", "Desktop/示例项目",
    "示例项目", ".agent-agent-f", "research-desk", "research-project-a",
]

# ---------- 四大块识别(关键词匹配,不认死模板标题) ----------
# 教训:~/Desktop/示例项目/初高衔接班/HANDOFF.md 用 "## ① 当前态" 而非
# "## 当前态(可覆写,保持最新)",被早期的精确串 grep 误判成"日志0/权限0/skill0"。
# 所以这里一律按关键词认块,允许 ①②③④ / 数字 / emoji 前缀与任意后缀。
BLOCKS = {
    "当前态": re.compile(r"^#{1,4}\s*[①②③④⑤0-9.、\s]*(当前态|current\s+state\b)", re.I),
    "必用skill": re.compile(r"^#{1,4}\s*[①②③④⑤0-9.、\s]*(必用\s*skill|skill\s*索引|必用技能|required\s+skills\b)", re.I),
    "权限链": re.compile(r"^#{1,4}\s*[①②③④⑤0-9.、\s]*(权限链|授权链|permissions\b)", re.I),
    "修改日志": re.compile(r"^#{1,4}\s*[①②③④⑤0-9.、\s]*(修改日志|变更日志|改动日志|modification\s+log\b)", re.I),
}

HEADING_RE = re.compile(r"^\s*#{1,6}\s+\S")


def section_end(lines, start_line):
    """Return the 1-based line number of the next Markdown heading.

    HANDOFFs may contain valid project-specific sections that are not one of
    the four required BLOCKS.  A section therefore ends at *any* Markdown
    heading, not merely at the next recognized required heading.
    """
    for line_no, line in enumerate(lines[start_line:], start_line + 1):
        if HEADING_RE.match(line):
            return line_no
    return len(lines) + 1

DATE_RE = re.compile(r"(20\d\d)[-/年.](\d{1,2})[-/月.](\d{1,2})")
# 权限链条目里的 发起者-执行者。中英文/数字/点,两侧各 1-20 字符
CHAIN_RE = re.compile(r"([A-Za-z0-9_.一-鿿]{1,20})\s*[-—]\s*([A-Za-z0-9_.一-鿿]{1,20})")
USER_CHAIN_RE = re.compile(r"用户\s*[-—]\s*[A-Za-z0-9_.一-鿿]{1,20}")
# 会被误当成"发起者-执行者"的噪声:任务 id / 日期 / 版本号区间 / 门槛编号
CHAIN_NOISE = re.compile(r"^(hd|task|wf|job|v\d|r\d|p\d|20\d\d|\d+)$", re.I)
MODEL_VERSION_LEFT = {"gpt", "claude", "gemini", "local-llm", "minimax", "llama"}
VERSION_TOKEN_RE = re.compile(r"^\d+(?:\.\d+)*$")
# 角色名后的括号注释,如 `mac本尊(model-x)-mm worker` / `用户-agent-e(model-y)`
PAREN_RE = re.compile(r"[（(][^）)]{0,40}[）)]")
# 真·列表条目行:标记后必须跟空白。用 startswith("*") 会把 markdown 粗体
# `**<date> 前不要派任务**` 这种正文当成条目 —— 初高衔接班就是这么被
# 误判成"日志最末日期晚于 mtime,改史嫌疑"的(<date> 查实)。
ITEM_RE = re.compile(r"^([-*+]\s|\|)")

# ---------- STALE_CONTENT(<date> 新增;独立等级,不进 P0/合规率) ----------
# 判据:目录里"最近有活动的文件" mtime 明显晚于 HANDOFF.md 修改日志最后一条日期,
# 说明内容真的在动但通稿没跟着记 —— 结构 100% 合规 ≠ 通稿有用。
#
# 阈值怎么定的(<date>,不是拍脑袋,见 result.md 完整分布):
#   对当时 314 份"有 HANDOFF.md"的真实工作区(两机合计)逐份计算
#   drift_days = 目录最新活动mtime - HANDOFF最后一条日志日期,只看正向漂移(内容新于日志,
#   这是唯一有风险的方向;负值=日志记得比内容还新,是正常收尾记账,不是腐烂):
#     正向漂移 P50=0.3d  P90=1.8d  P95=6.2d  P99=6.8d  max=6.92d(124/311 份为正向)
#   即:当前这批全是"operator directive"下正常维护的工作区,漂移几乎从不过一周。
#   STALE_CONTENT_DAYS 取观察到的最大值(6.92d)的 3 倍并取整 = 21 天(3周):
#   比"30天"这种拍脑袋数字更紧,但比实测天花板留出 3 倍安全边际,不会因为工作区
#   正常歇几天(周末/等上游)就被误报,只在内容真的走远了却没人补记时才响。
STALE_CONTENT_DAYS = 21
# 排除目录(在 EXCLUDE_PAT 之外,专门排掉"日志/临时/快照"类,别把巡检自己写的
# 日志文件/临时产物的 mtime 当成"内容还在动"的证据)
STALE_EXCLUDE_DIR_NAMES = {
    "logs", "log", "tmp", "temp", "snapshot", "snapshots", "cache",
    "backup", "backups", "__pycache__", "node_modules", ".git",
    ".venv", "venv", "dist", "build", ".gradle", "archive", "_archive",
    ".ai-bus", ".heartbeat", "query_logs", "inbox_images", "sessions",
}
# 运行期状态戳(<date> agent-c 实测新增):这些文件由常驻服务每拍重写,
# mtime 恒等于「刚才」,但它们**不是内容产物** —— 判据本意是「目录里产出了
# 新东西而通稿没跟上」,心跳戳跟产出无关。
# 不排掉的后果是结构性的:HANDOFF 永远追不上每分钟刷新的 mtime,
# 这类工作区必然**永久判不合格**,改多少次通稿都没用。
# 实测受害者(<date>,该 cron 已连续失败 19 天):
#   .coldstore-clerk / .coldstore-driver / .coldstore-spare 的 cron/ticker_last_success、
#   cron/ticker_heartbeat、cron/.tick.lock;keyboard-phone-relay 的 runtime-*.status。
# ★ 这不是放宽:同一次扫描里,真有新产物的工作区(示例项目/s5_review_v2 的
#   out/*/sheets.json、memory-service/miles 的 stats.json)照样被判出来。
# ★ 只按文件名精确匹配/窄正则,不碰任何业务产物后缀。
STALE_EXCLUDE_FILE_PAT = re.compile(
    r"(^runtime-[\w.-]+\.status$|^\.?tick\.lock$|^ticker_[\w-]+$"
    r"|_heartbeat$|_last_success$|^\.heartbeat_state\.json$)"
)
# 豁免标记:归档/冻结类工作区在 HANDOFF.md 任意处写一行含此关键字即豁免,
# 建议格式 `STALE_CONTENT_EXEMPT: 已归档/冻结,原因...`(自然语言写在冒号后,
# 判据只认关键字本身,不解析原因)。
STALE_EXEMPT_RE = re.compile(r"STALE_CONTENT_EXEMPT", re.I)

# ---------- EMPTY_FIELD(<date> 新增;独立等级,不进 P0/合规率/退出码) ----------
# 病根(用户 <date> 实测):结构 100% 合规 ≠ 通稿有用。307 份 HANDOFF 里 115 份(37.4%)
# 「做到哪:」后面真空,115 份「下一道门:」真空——scaffold 生成时模板字段存在,但 worker
# 没填内容。结构 lint 不查块里字段有没有内容,只看标题在不在,所以"合规率 100%"完全是
# 结构口径,内容口径从未测量。
#
# 判据取舍(不是拍脑袋,详见 ~/.coldstore/eval/handoff_content_20260805/distribution.md §3):
#   真进缺陷的字段集 = {这是什么, 产线, 做到哪, 下一道门}
#     这是什么 真空=0/307,只要写出字段行就有内容,真空=100% 异常
#     产线     真空=0/307(placeholder=「无」=合法,见下文);真空=100% 异常
#     做到哪   真空=115/307=37.4%,与用户抽测 200 份 75 份 (37.5%) 一致
#     下一道门 真空=115/307=37.4%,与做到哪同量级
#   不进判据的字段 = {卡点,所有 placeholder「无」,所有 absent}
#     卡点:用户明文认可「没有卡点」是合法留白;实测 113 vacuum + 58 placeholder=「无」=55.7%
#     都属合法(若强行判缺陷,会让过半工作区误报,无意义)
#     产线 placeholder「无」:规范明文允许填「无」,实测 85/307 这么写
#     absent:字段名都没出现的情况(如 初高衔接班 用「本目录 = ...」开头),不强制命名格式,
#     避免和 workspace-handoff skill 鼓励的多样化表达冲突
EMPTY_FIELDS = ("这是什么", "产线", "做到哪", "下一道门")
EMPTY_FIELD_PATTERNS = {
    "这是什么": re.compile(r"^[\s\-\|\*]*这是什么\s*[::]\s*(.*)$"),
    "产线":     re.compile(r"^[\s\-\|\*]*产线\s*(\([^)]*\))?\s*[::]\s*(.*)$"),
    "做到哪":   re.compile(r"^[\s\-\|\*]*做到哪\s*[::]\s*(.*)$"),
    "下一道门": re.compile(r"^[\s\-\|\*]*下一道门\s*[::]\s*(.*)$"),
}
# 「产线」允许的占位值:与 measure.py PLACEHOLDER_VALS 同口径,worker 填「无」是合法的
# (workspace-handoff 规范)。其它字段不允许 placeholder——只允许真空/有内容。
EMPTY_FIELD_PLACEHOLDER_OK = {"无", "N/A", "—", "-", "TODO"}
# `ws new` 会先落空游标，再由实际 worker 生成产物并用 `ws state` 收口。
# 解析视频与研究轮次实测常需约 15–20 分钟；若创建瞬间就报 EMPTY_FIELD，
# 每次巡检都会把正常在途建区当故障。只对 `ws` 同时创建且之后不改 mtime 的
# HANDOFF.md.lock 给 30 分钟宽限；旧管线没生成 lock 时回退 HANDOFF.md mtime。
# 超过宽限仍为空照常告警，孤儿区不会永久隐身。
EMPTY_FIELD_GRACE_SECONDS = 30 * 60


# ---------- 跨机一致性(<date> 新增;独立等级,不进 P0/合规率) ----------
# 判据:两机索引里同一相对路径都有 HANDOFF.md 的工作区(如 示例项目/初高衔接班),
# 若两侧通稿都没写清"数据主源在哪台机器",接手的人无法判断该信哪边的文件数/内容。
# 不强求固定字段名——沿用已经在用的自然写法(权威=/主源在/权威主干/唯一权威源等),
# 只要求"至少一侧提到了"就算合规;两侧都没提到才告警。不做任何自动同步。
SOURCE_DECL_RE = re.compile(
    r"主源|权威源|权威主干|权威\s*[:=：]|source[ -]of[ -]truth|authoritative\s+source", re.I
)


def peer_ssh_target():
    """返回 (ssh目标, 对侧$HOME) —— 与 ws 工具同一套双机约定,别再造一份。"""
    if platform.system() == "Darwin":
        return "user@host-b", "/home/user"
    return "user@host-a", "/Users/user"


def fetch_peer_handoffs(rel_paths):
    """给一批相对路径(相对各自 $HOME),一次 ssh 往返查对侧是否也有同名工作区的
    HANDOFF.md,有就带回内容。返回 {rel: body} 或 None(对侧不可达,调用方应静默跳过
    这项检查,不当成"两侧都缺声明"误报)。局域网 ssh,不算违反"零外网请求"
    (与本文件 --push 的 the LAN 例外同一口径)。"""
    if not rel_paths:
        return {}
    peer_ssh, _peer_home = peer_ssh_target()
    remote_script = (
        'while IFS= read -r rel; do '
        'f="$HOME/$rel/HANDOFF.md"; '
        'if [ -f "$f" ]; then echo "===CH_REL==="; echo "$rel"; '
        'echo "===CH_BODY==="; cat "$f"; echo "===CH_END==="; fi; '
        'done'
    )
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", peer_ssh,
             "bash -lc %s" % shlex.quote(remote_script)],
            input="\n".join(rel_paths), capture_output=True, text=True, timeout=25)
    except Exception:
        return None
    if r.returncode != 0 and not r.stdout.strip():
        return None
    out = {}
    for b in r.stdout.split("===CH_REL===\n")[1:]:
        try:
            rel_part, rest = b.split("===CH_BODY===\n", 1)
            body = rest.split("===CH_END===", 1)[0]
            out[rel_part.strip()] = body
        except Exception:
            continue
    return out


def dir_latest_content_mtime(path, handoff_path):
    """STALE_CONTENT 用:目录里(排除 HANDOFF.md 自身 + 日志/临时/快照类目录)
    最近活动文件的 mtime。「最近 N 个文件的最大值」在数学上就是目录整体最大值
    (N 越大越不会漏,取 max 时 N 不影响结果),这里直接算整体最大值,
    STALE_EXCLUDE_DIR_NAMES 之外不再单独限制 N。"""
    latest = None
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in STALE_EXCLUDE_DIR_NAMES
                   and not EXCLUDE_PAT.search(root + "/" + d + "/")]
        if EXCLUDE_PAT.search(root + "/"):
            continue
        if root != path and "HANDOFF.md" in files:
            dirs[:] = []
            continue
        if root[len(path):].count(os.sep) >= 3:
            dirs[:] = []
        for f in files:
            fp = os.path.join(root, f)
            if fp == handoff_path or f == "HANDOFF.md.lock" or f.endswith((".log", ".pid", ".sock")):
                continue
            if STALE_EXCLUDE_FILE_PAT.search(f):
                continue          # 运行期状态戳,不是内容产物(见常量处长注释)
            try:
                m = os.lstat(fp).st_mtime
            except OSError:
                continue
            if latest is None or m > latest:
                latest = m
    return latest


def last_log_date_from_text(text):
    """从 HANDOFF.md 全文里抠「修改日志」块最后一条条目行的日期(epoch)。
    复用 check_handoff 同一套「条目行首 30 字符内找日期」判据,避免正文里的
    未来日期被误读成条目(<date> 初高衔接班踩过的坑,同一坑不踩两次)。"""
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if BLOCKS["修改日志"].match(ln.strip()):
            start = i
            break
    if start is None:
        return None
    dates = []
    for l in lines[start:]:
        s = l.strip()
        if not ITEM_RE.match(s):
            continue
        m = DATE_RE.search(s[:30])
        if m:
            try:
                dates.append(datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))))
            except ValueError:
                pass
    if not dates:
        return None
    return max(dates).timestamp()


def check_empty_fields(hp):
    """EMPTY_FIELD 判据。返回 None(不触发:无当前态块/全合规/快照副本)或
    dict(触发:含空字段名列表 + 证据)。

    算法(同 measure.py 口径,保持判据与基线测量 1:1 对应):
      1. 找到「当前态」块;块不存在 -> None(缺块已由 BLOCKS 报,这里不重复报)
      2. 工作区若是快照副本 -> None(被 is_snapshot_copy 过滤,不算活工作区)
      3. 对每个 EMPTY_FIELDS 字段:
           absent = 字段行没出现 -> 不判(不同写法,见 distribution.md §3)
           vacuum = 字段行 val 空 + 下一非空行不是其缩进子项/段落续行 -> **缺陷**
           placeholder「无」= val 是 EMPTY_FIELD_PLACEHOLDER_OK 之一 -> 合法(只对产线)
           real = 有真实内容 -> 合法
      4. 若有任何一个字段真空 -> 返回 {"path": wsdir, "fields": [字段名...]}"""
    try:
        text = open(hp, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    wsdir = os.path.dirname(hp)
    if is_snapshot_copy(wsdir):
        return None
    lock_path = hp + ".lock"
    age_path = lock_path if os.path.exists(lock_path) else hp
    try:
        workspace_age = time.time() - os.path.getmtime(age_path)
        if 0 <= workspace_age < EMPTY_FIELD_GRACE_SECONDS:
            return None
    except OSError:
        pass
    lines = text.splitlines()

    # 找「当前态」块起止
    start = None
    for i, ln in enumerate(lines):
        if BLOCKS["当前态"].match(ln.strip()):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        for name, rx in BLOCKS.items():
            if name != "当前态" and rx.match(lines[i].strip()):
                end = i
                break
        if end != len(lines):
            break
    block_lines = lines[start:end]

    empty = []
    for field in EMPTY_FIELDS:
        rx = EMPTY_FIELD_PATTERNS[field]
        locs = []
        for idx, ln in enumerate(block_lines):
            m = rx.match(ln.strip())
            if m:
                val = (m.group(2) if field == "产线" else m.group(1)).strip()
                locs.append((idx, val))
        if not locs:
            continue                      # absent = 字段行不存在,不判(见上 §3)
        idx, val = locs[-1]                # 取最后出现
        if val:
            # 真空 = 同 val 长度 0 才算;有内容(含占位)都合法
            continue
        # val 是空字符串——检查下一非空行是不是缩进子项/段落续行(多行写法)
        multiline = False
        for j in range(idx + 1, len(block_lines)):
            nxt = block_lines[j]
            if not nxt.strip():
                continue
            # 下一行是另一字段名行 -> 真空
            if any(EMPTY_FIELD_PATTERNS[g].match(nxt.strip()) for g in EMPTY_FIELDS):
                break
            # 下一行是 ## 块标题 -> 真空
            if any(rx.match(nxt.strip()) for name, rx in BLOCKS.items() if name != "当前态"):
                break
            # 下一行有缩进/段落续行 -> 多行内容,不算真空
            if nxt.startswith(("  ", "\t")) or not nxt.startswith(("-", "*", "|", "#")):
                multiline = True
                break
            break
        if multiline:
            continue
        empty.append(field)
    if not empty:
        return None
    return {"path": wsdir, "fields": empty}


# ---------- CROSS_DEP_UNDECLARED(<date> 新增;独立等级,不进 P0/合规率/退出码) ----------
# 病根(<date> 实测):Mac 34/54、hostb 37/320 份通稿在正文里裸写别的工作区的绝对
# 路径,全部散在自然语言里,没有任何结构化字段。后果是"改 A 会不会崩 B"在机器侧完全
# 不可查询——只能靠人读完整篇通稿再自己联想。
# 判据故意收得很紧:只有当被提到的那个路径**本身也是一个已登记工作区**(自己有
# HANDOFF.md)时才算依赖。提到普通文件/日志/备份不算——否则告警会被 ~/miniconda3/bin/python
# 这类噪声淹没(全路径口径下 Mac 一份通稿最多提到 15 条外部路径)。
# 父子工作区(如 产线/产物/q123 提到 产线)是结构包含关系,不是跨区依赖,排除。
# 声明格式(告警文案里自带,不依赖外部文档):在「当前态」块写一行
#     - 依赖: /abs/path1, /abs/path2      # 本工作区读它们的产物,它们变了我会崩
#     - 被依赖: /abs/path3                # 它们读我的产物,我变了它们会崩
# 只要路径出现在 依赖:/被依赖: 任一行的值里就算已声明,不校验方向对不对(方向是人的
# 判断,机器不该替人拍板)。
DEP_FIELD_RE = re.compile(r"^[\s\-\|\*>]*(依赖|被依赖)\s*[:：]\s*(.*)$")
# `~` 后面必须跟 `/`,把「~8s」「~140 条」这类"约等于"写法挡在外面(实测这是裸正则
# 抓路径时最主要的假阳性来源)。反引号/星号/引号/中文括号都是终止符,避免把 markdown
# 强调符 `**~/x**` 的星号吃进路径里(会造出一条永远不存在的假死路径)。
CLAIM_PATH_RE = re.compile(
    r"(?<![\w`~])(?:~|/(?:home|Users|Volumes|mnt|data|srv|opt|media))"
    r"/[^\s`'\"*()（）【】「」、,，;；|]+")
CLAIM_TRIM = u"。.,，;；:：)）】」』、!！?？…-*`\"'/"


def _block_lines(lines, name):
    """取某一大块的正文行(不含块标题)。块边界一律交给 BLOCKS,不另立一套正则。"""
    start = None
    for i, ln in enumerate(lines):
        if BLOCKS[name].match(ln.strip()):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        s = lines[i].strip()
        if any(rx.match(s) for n, rx in BLOCKS.items() if n != name):
            end = i
            break
    return lines[start + 1:end]


def claimed_paths(text):
    """正文里声称的绝对路径,返回 [(原文, 展开后的绝对路径)]。"""
    out = []
    for m in CLAIM_PATH_RE.finditer(text):
        raw = m.group(0)
        p = raw.rstrip(CLAIM_TRIM)
        if not p or any(c in p for c in u"*<>${}"):
            continue
        exp = HOME + p[1:] if p.startswith(u"~") else p
        out.append((raw, exp))
    return out


def is_foreign_home(p):
    """路径属于对侧机器的 home(如 Mac 上看到 /home/user/...)。
    对侧的文件在本机当然不存在,拿它当腐烂证据是错的,所以腐烂判据要排除。"""
    for root in ("/home/", "/Users/"):
        if p.startswith(root) and p != HOME and not p.startswith(HOME + "/"):
            return True
    return False


def _ws_of(p, known_ws):
    """路径落在哪个已登记工作区里(取最近的祖先);都不在返回 None。"""
    q = p.rstrip("/")
    while q and q != "/" and q != HOME:
        if q in known_ws:
            return q
        parent = os.path.dirname(q)
        if parent == q:
            break
        q = parent
    return None


def check_cross_dep(hp, known_ws):
    """CROSS_DEP_UNDECLARED 判据。known_ws = 本机所有已登记工作区目录集合。
    返回 None 或 {"path": 工作区, "deps": [未声明的外部工作区...]}。"""
    try:
        text = open(hp, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    wsdir = os.path.dirname(hp)
    if is_snapshot_copy(wsdir) or STALE_EXEMPT_RE.search(text):
        return None
    # 依赖是**当前结构**，不是历史事件。修改日志/权限链里的旧路径只说明曾经
    # 操作过彼处；把它们当现役依赖会让已结束任务永久挂告警。与 ROT_SUSPECT
    # 一致，只读「当前态」块；依赖声明也必须落在这个块里。
    cur = _block_lines(text.splitlines(), u"当前态")
    if cur is None:
        return None
    body = u"\n".join(cur)
    declared = u""
    for ln in cur:
        m = DEP_FIELD_RE.match(ln)
        if m:
            declared += u" " + m.group(2)
    hits = []
    for raw, p in claimed_paths(body):
        # 引用绝大多数指向工作区里的**某个文件**(`~/webshell/HANDOFF.md`、
        # `.../产物/out.jsonl`),不是工作区目录本身。所以要沿父目录上溯,取最近的
        # 已登记工作区。<date> 自检用例 cross_dep__fail_undeclared_foreign_workspace
        # 就是逮住了这个漏判:早先版本直接拿整条路径去比对 known_ws,恒不命中。
        p = _ws_of(p, known_ws)
        if p is None:
            continue
        if p == wsdir or p.startswith(wsdir + "/") or wsdir.startswith(p + "/"):
            continue
        if is_snapshot_copy(p):
            # 引用自己的历史备份(app-a -> app-a_backups/pre-*)
            # 不是"改 A 崩 B"的依赖,备份本来就是冻结副本。实测不排除的话 Mac 上
            # 一条告警就挂 4 个备份目录,把真依赖挤掉。
            continue
        if p in declared or raw.rstrip(CLAIM_TRIM) in declared:
            continue
        if p not in hits:
            hits.append(p)
    if not hits:
        return None
    return {"path": wsdir, "deps": sorted(hits)}


# ---------- ROT_SUSPECT(<date> 新增;独立等级,不进 P0/合规率/退出码) ----------
# 病根(<date> 实测):STALE_CONTENT 用 mtime 判漂移,而 <date>/05 的批量通稿重建把
# 所有工作区的日志时钟一起归零,于是两机 STALE_CONTENT 同时检出 0 项——这个闸在过去
# 三周零信息量。腐烂的真正表征不是"多久没动",是"通稿现在说的话已经不成立"。
# 三条不依赖 mtime 的证据:
#   DEAD_PATH  「当前态」声称的本机绝对路径已不存在
#   DEAD_PORT  「当前态」声称 localhost/127.0.0.1:PORT 但本机没人在听
#   DONE_GATE  「下一道门」指向的 task-id 已经躺在 dispatch/done|failed 里(门已过完)
# 只取「当前态」块:只有当前态是对现状的断言。权限链/修改日志是历史,历史提到已删除的
# 路径完全正常——实测全文口径会把最活跃的 ~/.coldstore/bin 判成死路径 5 条,全部来自历史
# 日志行,是纯误报。
# 对侧 home 路径(/home/user/... 在 Mac 上)一律跳过:本机不存在是正常的。
# 端口枚举不到时整条 DEAD_PORT 跳过(fail-open),不制造假腐烂。
# 豁免沿用 STALE_CONTENT_EXEMPT 标记,不新造一套。
LOCAL_PORT_RE = re.compile(r"(?:localhost|127\.0\.0\.1)[:：](\d{2,5})")
ABSENCE_HINT_RE = re.compile(
    r"(不存在|未安装|缺失|断链|已删|已移除|已过期|过期|已退役|退役|无人监听)", re.I)
TASKID_RE = re.compile(r"\bhd-\d{8}-\d{6}-[a-z0-9]{4}\b")
_PORTS_CACHE = []
_DONE_CACHE = []


def listening_ports():
    """本机在听的 TCP 端口集合;枚举不到返回 None -> 判据跳过端口项。"""
    if _PORTS_CACHE:
        return _PORTS_CACHE[0]
    ports = set()
    got = False
    for cmd in ("ss -H -ltn 2>/dev/null", "netstat -an -p tcp 2>/dev/null",
                "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null"):
        out = sh(cmd)
        if not out.strip():
            continue
        for m in re.finditer(r"[:.](\d{2,5})\b", out):
            ports.add(m.group(1))
        got = True
        if ports:
            break
    _PORTS_CACHE.append(ports if got else None)
    return _PORTS_CACHE[0]


def done_task_ids():
    """dispatch/done + failed 里的 task-id 集合(目录名即 id)。"""
    if _DONE_CACHE:
        return _DONE_CACHE[0]
    ids = set()
    for b in ("done", "failed"):
        d = os.path.join(HOME, ".coldstore", "dispatch", b)
        try:
            ids |= set(os.listdir(d))
        except OSError:
            pass
    _DONE_CACHE.append(ids)
    return ids


def check_rot(hp):
    """ROT_SUSPECT 判据。返回 None 或
    {"path":.., "dead_paths":[..], "dead_ports":[..], "done_gates":[..]}。"""
    try:
        text = open(hp, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    wsdir = os.path.dirname(hp)
    if is_snapshot_copy(wsdir) or STALE_EXEMPT_RE.search(text):
        return None
    lines = text.splitlines()
    cur = _block_lines(lines, u"当前态")
    if cur is None:
        return None
    body = u"\n".join(cur)

    # 「卡点:某路径缺失/过期」的缺失正是当前断言，不是通稿腐烂；
    # 显式写了已退役的端口同理。只豁免同一行里被点名的路径/端口，
    # 不做整份文档的宽泛豁免，其余死断言仍照常抓。
    explicitly_absent_paths = set()
    explicitly_retired_ports = set()
    for ln in cur:
        if not ABSENCE_HINT_RE.search(ln):
            continue
        for _raw, p in claimed_paths(ln):
            explicitly_absent_paths.add(p.rstrip("/"))
        explicitly_retired_ports.update(LOCAL_PORT_RE.findall(ln))

    dead_paths = []
    for raw, p in claimed_paths(body):
        p = p.rstrip("/")
        if p in explicitly_absent_paths:
            continue
        if is_foreign_home(p) or len(p) < 12:
            continue
        # 顶层根在本机不存在 -> 整个命名空间是别处的,不可判。
        # 实测这一条挡掉了手机侧 adb 路径:Mac 上 /data 根本不存在,而
        # /data/system/packages.xml、/data/local/tmp/*.apk 在手机上是真实存在的,
        # 不加这条会把 app-a / webshell 两个活工作区判成腐烂(纯误报)。
        # hostb 上 /data 是真实挂载(comfyui 等),所以那边照常检查,不是一刀切豁免。
        root = "/" + p.strip("/").split("/")[0]
        if not os.path.isdir(root):
            continue
        if not os.path.exists(p) and p not in dead_paths:
            dead_paths.append(p)

    dead_ports = []
    live = listening_ports()
    if live is not None:
        for port in sorted(set(LOCAL_PORT_RE.findall(body))):
            if port in explicitly_retired_ports:
                continue
            if port not in live:
                dead_ports.append(port)

    done_gates = []
    done = done_task_ids()
    for ln in cur:
        m = EMPTY_FIELD_PATTERNS[u"下一道门"].match(ln.strip())
        if not m:
            continue
        for tid in TASKID_RE.findall(m.group(1)):
            if tid in done and tid not in done_gates:
                done_gates.append(tid)

    if not (dead_paths or dead_ports or done_gates):
        return None
    return {"path": wsdir, "dead_paths": sorted(dead_paths),
            "dead_ports": dead_ports, "done_gates": done_gates}


def check_stale_content(hp):
    """返回 None(不触发/已豁免/信息不足)或 dict(触发,含证据数字)。"""
    try:
        text = open(hp, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    if STALE_EXEMPT_RE.search(text):
        return None
    lld = last_log_date_from_text(text)
    if lld is None:
        return None
    wsdir = os.path.dirname(hp)
    dlm = dir_latest_content_mtime(wsdir, hp)
    if dlm is None:
        return None
    drift_days = (dlm - lld) / 86400.0
    if drift_days <= STALE_CONTENT_DAYS:
        return None
    return {
        "path": wsdir,
        "drift_days": round(drift_days, 1),
        "dir_latest": time.strftime("%F", time.localtime(dlm)),
        "last_log_date": time.strftime("%F", time.localtime(lld)),
    }


def cross_host_source_missing(local_paths):
    """跨机同名工作区,若两侧 HANDOFF.md 都没写清"数据主源在哪台机器"就告警。
    返回 (records, degraded)。degraded=True 表示对侧不可达,本轮该检查整体跳过
    (查不到 ≠ 两侧都缺声明,不能把"没查"误判成"没写")。"""
    rels = []
    for p in local_paths:
        if p.startswith(HOME + os.sep):
            rels.append(p[len(HOME) + 1:])
    peer = fetch_peer_handoffs(rels)
    if peer is None:
        return [], True
    out = []
    for rel, peer_body in peer.items():
        local_path = os.path.join(HOME, rel)
        local_hp = os.path.join(local_path, "HANDOFF.md")
        try:
            local_body = open(local_hp, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if SOURCE_DECL_RE.search(local_body) or SOURCE_DECL_RE.search(peer_body):
            continue
        out.append({"path": local_path, "rel": rel})
    return out, False


def has_chain(line):
    """行内是否含真正的 `发起者-执行者`。
    只看权限链最可能出现的位置(第 1-2 个 | 字段,或行首 60 字符),
    并剔除 task-20260723 / R1-R6 / v1-v7 / P0-P1 这类噪声连字符。
    教训:早期版本只做全行 CHAIN_RE.search,把 `用户 → default(...R1-R6...)`
    这种**箭头写法**误判成合规——箭头不是规范要求的连字符格式。
    教训2(<date>):角色名带括号注释时误杀。`mac本尊(model-x)-mm worker` 是
    合法的发起者-执行者,但 `)` 不在 CHAIN_RE 字符类里,连字符左侧匹配不上 →
    误报"缺格式"。agent-g_review / agent-g-wind-critic-pilot 两台都因此挂 P1。
    修法:判定前剥掉中英文括号注释(只影响判定,不改文件)。"""
    seg = line
    if line.count("|") >= 2:
        seg = "|".join(line.split("|")[:2])
    else:
        seg = line[:60]
    seg = PAREN_RE.sub("", seg)
    for a, b in CHAIN_RE.findall(seg):
        if CHAIN_NOISE.match(a) or CHAIN_NOISE.match(b):
            continue
        # `gpt-5.6-sol` / `local-llm-3.5` 是模型版本，不是发起者-执行者。
        # 只在“已知模型族 + 纯数字版本”这一精确形态下排除，因此
        # `用户-codex`、`agent-k-mm` 等真实角色链仍正常通过。
        if a.lower() in MODEL_VERSION_LEFT and VERSION_TOKEN_RE.match(b):
            continue
        return True
    return False


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=120).stdout
    except Exception:
        return ""


def dir_stats(path):
    """返回 (文件数, 最旧mtime, 最新mtime)。只读,跳过排除目录。

    子目录若自带 HANDOFF.md，说明它已经是独立工作区；其产物归它自己，不能再
    把父工作区判成“内容更新而通稿没跟上”。这与 ws 的最深工作区归属规则一致。
    """
    n, oldest, newest = 0, None, None
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not EXCLUDE_PAT.search(root + "/" + d + "/")]
        if EXCLUDE_PAT.search(root + "/"):
            continue
        if root != path and "HANDOFF.md" in files:
            dirs[:] = []
            continue
        if root[len(path):].count(os.sep) >= 3:
            dirs[:] = []
        for f in files:
            fp = os.path.join(root, f)
            try:
                m = os.lstat(fp).st_mtime
            except OSError:
                continue
            n += 1
            oldest = m if oldest is None or m < oldest else oldest
            newest = m if newest is None or m > newest else newest
            if n > 20000:
                return n, oldest, newest
    return n, oldest, newest


def dispatch_refs():
    """路径 -> 引用过它的不同派单数。证据来自本地 dispatch 记录,零网络。"""
    counts = {}
    pat = re.compile(r"(?:/Users/[A-Za-z0-9_.-]+|/home/[A-Za-z0-9_.-]+|~)"
                     r"/[A-Za-z0-9_.一-鿿-]+(?:/[A-Za-z0-9_.一-鿿-]+)*")
    for state in ("done", "failed"):
        d = os.path.join(DISPATCH, state)
        if not os.path.isdir(d):
            continue
        for tid in os.listdir(d):
            p = os.path.join(d, tid, "prompt.md")
            if not os.path.isfile(p):
                continue
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            seen = set()
            for m in pat.findall(txt):
                m = re.sub(r"^~", HOME, m)
                # 归一到 $HOME 前缀,吃掉跨机 /home/user 与 /Users/xxx 的差异
                m = re.sub(r"^/(?:Users|home)/[A-Za-z0-9_.-]+", HOME, m)
                seen.add(m)
            for m in seen:
                counts[m] = counts.get(m, 0) + 1
    return counts


def candidates(refs):
    out = {}
    for root, _depth in SCAN_ROOTS:
        if not os.path.isdir(root):
            continue
        if (os.path.basename(root) not in DENY_NAMES and root != HOME
                and not is_nonworkspace_path(root)):
            out.setdefault(root, None)          # 根自己也是候选(如 ~/Desktop/示例项目)
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for e in entries:
            p = os.path.join(root, e)
            if not os.path.isdir(p) or os.path.islink(p):
                continue
            if e in DENY_NAMES or EXCLUDE_PAT.search(p + "/") or is_nonworkspace_path(p):
                continue
            if is_snapshot_copy(p):        # 备份区内部的冻结副本,不是活工作区
                continue
            out.setdefault(p, None)
    return out


def second_source_index():
    """第二来源:skill / 已有 HANDOFF.md / ~/.coldstore/notes 里提到过的路径全文。
    返回一大坨文本,后面用子串命中判定。零网络,只读。"""
    chunks = []
    for pat in ("%s/.claude/skills/*/SKILL.md" % HOME,
                "%s/skills-core/skills/*/SKILL.md" % HOME,
                "%s/.coldstore/notes/*" % HOME):
        chunks.append(sh("cat %s 2>/dev/null" % pat))
    chunks.append(sh("find %s -name HANDOFF.md -not -path '*/.git/*' "
                     "-not -path '*/node_modules/*' -exec cat {} + 2>/dev/null" % HOME))
    return "\n".join(chunks)


def is_workspace(path, refs, srcidx):
    """返回 (够格?, 证据串)。判据见文件头 docstring。"""
    ev = []
    nref = 0
    for k, v in refs.items():
        if k == path or k.startswith(path + "/"):
            nref = max(nref, v)
    if nref >= 2:
        ev.append("dispatch单引用x%d" % nref)

    n, old, new = dir_stats(path)
    if n < MIN_FILES:
        return False, "文件数%d<%d(空壳)" % (n, MIN_FILES)

    span = (new - old) / 86400.0 if (old and new) else 0.0
    # 第二来源:被 skill / HANDOFF / notes 用路径名点过名
    short = path.replace(HOME + "/", "")
    cited = (short in srcidx) or (path in srcidx) or ("~/" + short in srcidx)
    if span > SPAN_DAYS and cited:
        ev.append("mtime跨度%.0fd/文件%d + 被skill/HANDOFF/notes点名" % (span, n))
    elif span > SPAN_DAYS and nref == 1:
        ev.append("mtime跨度%.0fd/文件%d + dispatch单引用x1" % (span, n))

    if ev:
        return True, "; ".join(ev)
    return False, "文件%d/跨度%.0fd,无第二来源(不判为多agent工作区)" % (n, span)


def check_handoff(hp):
    """逐份符合度。返回 defects 列表。"""
    defects = []
    try:
        lines = open(hp, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError as e:
        # <date> agent-c:区分「扫描途中被删」与「真读不了」。
        # 本 lint 扫 693 份要跑几分钟,而视频线产物目录(产物/qcln*)由 GC 持续清理,
        # 扫描窗口内必然会撞上正在消失的目录 —— 那是 GC 正常工作,不是通稿缺陷。
        # 旧判据一律记成 defect,而「读取失败」会被算进 P0,于是这条 cron 随机 rc=1,
        # 实测连续失败 20 天里就混着这类竞态(同一天里我手跑 693/693 rc=0、
        # 经 wrapper 跑却 rc=1,差别只是有没有撞上 GC)。
        # ★ 只豁免「现在真的不存在了」这一种:路径还在却读不了(权限/损坏/坏盘)
        #   照旧判 defect,不放水。
        if not os.path.exists(hp):
            return []
        return ["读取失败: %s" % e]

    found = {}
    for i, ln in enumerate(lines, 1):
        for name, rx in BLOCKS.items():
            if name not in found and rx.match(ln.strip()):
                found[name] = i
    for name in BLOCKS:
        if name not in found:
            defects.append("缺块[%s]" % name)

    # 权限链格式
    if "权限链" in found:
        start = found["权限链"]
        end = section_end(lines, start)
        body = [(i, lines[i - 1]) for i in range(start + 1, min(end, len(lines) + 1))]
        # 续行合并(<date>):条目写不下换行时,续行以 `|` 开头(如 skills-core
        # L63-64 的 `...(依据 arXiv:...)` + `| 单次(判据入库)`)。早期版本把续行当独立
        # 条目判,必然"缺发起者-执行者"——两台机器的 skills-core 都因此挂 P0 误报。
        items = []
        for i, l in body:
            s = l.strip()
            if ITEM_RE.match(s) and not s.startswith("|"):
                items.append([i, s])
            elif s.startswith("|"):
                if items:
                    items[-1][1] += " " + s      # 并入上一条,不单独判
                else:
                    items.append([i, s])         # 块首即 | :可能是表格,仍单独判
        if not items:
            defects.append("L%d 权限链块无条目" % start)
        for i, l in items:
            if not has_chain(l):
                defects.append("L%d 权限链缺'发起者-执行者'格式(规范铁律3): %s"
                               % (i, l.strip()[:46]))
            elif USER_CHAIN_RE.search(l) and not DATE_RE.search(l):
                defects.append("L%d 用户指令类权限链缺日期(单次短效必须带日期): %s"
                               % (i, l.strip()[:40]))

    # ⭐ 验收标记
    if "必用skill" in found:
        start = found["必用skill"]
        end = section_end(lines, start)
        seg = "\n".join(lines[start:min(end - 1, len(lines))])
        if not seg.strip():
            defects.append("L%d 必用skill块为空" % start)
        elif "⭐" not in seg and "★" not in seg:
            defects.append("L%d 必用skill无⭐验收标记(规范铁律4)" % start)

    # 当前态是否过期:目录最新产物 mtime vs HANDOFF 最后修改
    wsdir = os.path.dirname(hp)
    new = dir_latest_content_mtime(wsdir, hp)
    try:
        hm = os.lstat(hp).st_mtime
    except OSError:
        hm = 0
    if new and (new - hm) > STALE_DAYS * 86400:
        defects.append("当前态疑似过期:目录最新产物 %s,HANDOFF 最后改 %s(差%.0f天)"
                       % (time.strftime("%F", time.localtime(new)),
                          time.strftime("%F", time.localtime(hm)),
                          (new - hm) / 86400.0))

    # 只追加检查:日志里最后一条日期 晚于 HANDOFF mtime => 不可能,说明手改过
    if "修改日志" in found:
        start = found["修改日志"]
        end = section_end(lines, start)
        seg = lines[start:end - 1]
        dates = []
        for l in seg:
            # 只认「条目行行首」的日期(<date>)。早期版本对日志块做全文 grep,
            # 把正文里提到的**未来日期**当成条目日期 → 误判"改史嫌疑"。真实误伤:
            # 示例项目/初高衔接班 日志正文写"账号封禁将于 <date> 解除",被读成
            # 日志最末条目日期晚于 mtime。日期必须出现在条目行前 30 字符内才算。
            s = l.strip()
            if not ITEM_RE.match(s):
                continue
            m = DATE_RE.search(s[:30])
            if m:
                try:
                    dates.append(datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))))
                except ValueError:
                    pass
        if not dates:
            defects.append("L%d 修改日志无带日期条目" % found["修改日志"])
        elif hm:
            last = max(dates)
            hdt = datetime.fromtimestamp(hm)
            if last > hdt + timedelta(days=1):
                defects.append("日志最末日期 %s 晚于文件 mtime %s — 改史嫌疑"
                               % (last.strftime("%F"), hdt.strftime("%F")))
    return defects


def priority(path):
    rel = path.replace(HOME + "/", "")
    for m in P0_MARKERS:
        if rel == m or rel.startswith(m + "/") or rel.endswith("/" + m):
            return "P0"
    return "P1"


# ==================== 告警层 ====================

def _load_state():
    try:
        with open(STATEFILE, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        s = {}
    s.setdefault("issues", {})     # key -> {first: 日期, rounds: n, last: 日期}
    s.setdefault("last_push", {})  # {date, fingerprint, rate}
    return s


def _save_state(s):
    try:
        os.makedirs(STATEDIR, exist_ok=True)
        tmp = STATEFILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=1)
        os.replace(tmp, STATEFILE)
    except OSError as e:
        sys.stderr.write("handoff_lint: 状态写入失败 %s\n" % e)


def _issue_keys(missing, noncompliant):
    """只追 P0。P1 数量大且多为基础设施目录,天天推等于刷屏。"""
    ks = {}
    for m in missing:
        if m["priority"] == "P0":
            ks["MISS|" + m["path"]] = "缺HANDOFF %s" % m["path"].replace(HOME, "~")
    for r in noncompliant:
        if r["priority"] == "P0":
            ks["NC|" + r["path"]] = "不合规 %s (%s)" % (
                r["path"].replace(HOME, "~"), r["defects"][0][:34] if r["defects"] else "")
    return ks


def _update_streaks(state, keys, today):
    """返回 (新增key列表, 老问题key->连续轮数)。消失的问题清出状态。"""
    issues, fresh, aging = state["issues"], [], {}
    for k in list(issues):
        if k not in keys:
            del issues[k]                       # 修好了,清账
    for k in keys:
        rec = issues.get(k)
        if rec is None:
            issues[k] = {"first": today, "rounds": 1, "last": today}
            fresh.append(k)
        else:
            if rec.get("last") != today:        # 同日重跑不重复计轮
                rec["rounds"] = rec.get("rounds", 1) + 1
                rec["last"] = today
            aging[k] = rec["rounds"]
    return fresh, aging


def _days_between(a, b):
    try:
        return (datetime.strptime(a, "%Y-%m-%d") - datetime.strptime(b, "%Y-%m-%d")).days
    except Exception:
        return 999


def push_alert(missing, noncompliant, rate, total, force=False):
    """P0 告警推手机。返回 (推了吗, 原因)。全绿不推;老问题退避复推。"""
    keys = _issue_keys(missing, noncompliant)
    state = _load_state()
    today = time.strftime("%Y-%m-%d")
    fresh, aging = _update_streaks(state, keys, today)

    if not keys:
        # 全绿:上次推过问题、这次干净 => 推一条"清零"回执再闭嘴
        cleared = bool(state["last_push"].get("fingerprint"))
        state["last_push"] = {}
        _save_state(state)
        if cleared or force:
            _send("✅ HANDOFF P0 清零", "%s | 合规率 %.1f%% (%d 份)\nP0 缺失/不合规均为 0。"
                  % (os.uname().nodename, rate, total), "ok")
            return True, "cleared"
        return False, "全绿且此前也无问题,不推"

    fp = "|".join(sorted(keys))
    last = state["last_push"]
    stale_days = _days_between(today, last.get("date", "1970-01-01"))
    worst = max(aging.values()) if aging else 1
    # 退避:挂 1 轮天天提醒,挂 2 轮隔 3 天,挂 >=4 轮隔 7 天(避免刷屏但绝不静默)
    step = NAG_STEPS[0] if worst <= 1 else (NAG_STEPS[1] if worst < 4 else NAG_STEPS[2])

    why = None
    if force:
        why = "强制"
    elif fresh:
        why = "新增 %d 项" % len(fresh)
    elif fp != last.get("fingerprint"):
        why = "问题集合变化"
    elif rate < last.get("rate", 100) - 0.5:
        why = "合规率下滑 %.1f→%.1f" % (last.get("rate", 100), rate)
    elif stale_days >= step:
        why = "挂 %d 轮未修(退避 %dd 到期)" % (worst, step)
    if not why:
        _save_state(state)
        return False, "已推过且无恶化(最久挂%d轮,下次%d天后)" % (worst, step - stale_days)

    lvl = "err" if worst >= 3 else "warn"
    mark = "★" * min(worst, 3)
    title = "%s HANDOFF P0 %d 项%s" % (mark or "⚠️", len(keys),
                                       "·最久挂%d轮" % worst if worst > 1 else "")
    lines = ["%s | 合规率 %.1f%% (%d 份) | 触发:%s" % (os.uname().nodename, rate, total, why)]
    for k in sorted(keys, key=lambda x: -state["issues"].get(x, {}).get("rounds", 1))[:8]:
        n = state["issues"].get(k, {}).get("rounds", 1)
        flag = " ←挂%d轮!" % n if n >= 2 else (" [新]" if k in fresh else "")
        lines.append("· %s%s" % (keys[k], flag))
    if len(keys) > 8:
        lines.append("· …另 %d 项,详见 ws lint" % (len(keys) - 8))
    if worst >= 3:
        lines.append("⛔ 已挂≥3轮无人修:工作区闸在天天拦单空转,请派修或降级。")

    ok = _send(title, "\n".join(lines), lvl)
    if ok:
        state["last_push"] = {"date": today, "fingerprint": fp, "rate": rate}
    _save_state(state)
    return ok, why


def _send(title, body, level):
    if not os.access(PUSH_BIN, os.X_OK):
        sys.stderr.write("handoff_lint: 找不到 notify_push(%s),告警未送达\n" % PUSH_BIN)
        return False
    try:
        r = subprocess.run([PUSH_BIN, "--role", PUSH_ROLE, "--title", title,
                            "--body", body, "--level", level],
                           capture_output=True, text=True, timeout=25)
        if r.returncode != 0:
            sys.stderr.write("handoff_lint: 推送失败 rc=%d %s\n"
                             % (r.returncode, (r.stderr or "")[:200]))
            return False
        return True
    except Exception as e:
        sys.stderr.write("handoff_lint: 推送异常 %s\n" % e)
        return False


def main():
    ap = argparse.ArgumentParser(description="HANDOFF.md 覆盖率+符合度硬闸(只读,零外网)")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--quiet", action="store_true", help="只在有问题时输出")
    ap.add_argument("--log", action="store_true", help="追加写 ~/.coldstore/logs/handoff_lint.log")
    ap.add_argument("--push", action="store_true",
                    help="P0 有缺失/不合规时推手机(带挂单轮数与退避,全绿不推)")
    ap.add_argument("--push-force", action="store_true", help="无视退避强制推一条(自检用)")
    ap.add_argument("--no-cross-host", action="store_true",
                    help="跳过跨机 ssh 主源声明检查(局域网不可达/自测用)")
    ap.add_argument("--explain", action="store_true", help="打印判据说明后退出")
    args = ap.parse_args()

    if args.explain:
        print(__doc__)
        return 0

    refs = dispatch_refs()
    srcidx = second_source_index()
    cands = candidates(refs)

    missing, noncompliant, ok = [], [], []
    for p in sorted(cands):
        good, ev = is_workspace(p, refs, srcidx)
        hp = os.path.join(p, "HANDOFF.md")
        has = os.path.isfile(hp)
        if not good and not has:
            continue
        if not has:
            missing.append({"path": p, "evidence": ev, "priority": priority(p)})
        else:
            d = check_handoff(hp)
            rec = {"path": p, "evidence": ev, "priority": priority(p), "defects": d}
            (noncompliant if d else ok).append(rec)

    # 已有 HANDOFF 但不在候选扫描范围(深层子目录)的,补扫一遍
    extra = sh("find %s -name HANDOFF.md -not -path '*/node_modules/*' "
               "-not -path '*/.git/*' -not -path '*/.venv/*' 2>/dev/null" % HOME)
    known = {r["path"] for r in ok} | {r["path"] for r in noncompliant}
    snapshot_skipped = []
    for line in extra.splitlines():
        line = line.strip()
        if not line or EXCLUDE_PAT.search(line) or is_nonworkspace_path(line):
            continue
        wd = os.path.dirname(line)
        if wd in known or "/dispatch/done/" in wd or "/dispatch/failed/" in wd \
           or "/dispatch/work/" in wd or "/dispatch/running/" in wd \
           or "/archive/" in wd or "/tmp/rebuild-pack" in wd:
            continue
        if is_snapshot_copy(wd):
            snapshot_skipped.append(wd)   # 不静默:下面报告里会列出条数
            continue
        d = check_handoff(line)
        rec = {"path": wd, "evidence": "已有HANDOFF(深层)", "priority": priority(wd),
               "defects": d}
        (noncompliant if d else ok).append(rec)

    p0_missing = [m for m in missing if m["priority"] == "P0"]
    total = len(ok) + len(noncompliant)
    rate = (100.0 * len(ok) / total) if total else 100.0

    # ---------- STALE_CONTENT + 跨机主源声明 + EMPTY_FIELD:独立等级,不进 rate/exit code ----------
    all_hp_paths = sorted({r["path"] for r in ok} | {r["path"] for r in noncompliant})
    stale_content = []
    empty_fields = []
    cross_dep = []
    rot_suspect = []
    known_ws = {p.rstrip("/") for p in all_hp_paths}
    for p in all_hp_paths:
        hp = os.path.join(p, "HANDOFF.md")
        sc = check_stale_content(hp)
        if sc:
            stale_content.append(sc)
        ef = check_empty_fields(hp)
        if ef:
            empty_fields.append(ef)
        cd = check_cross_dep(hp, known_ws)
        if cd:
            cross_dep.append(cd)
        rt = check_rot(hp)
        if rt:
            rot_suspect.append(rt)
    cross_host, cross_degraded = ([], True) if args.no_cross_host \
        else cross_host_source_missing(all_hp_paths)

    if args.json:
        out = json.dumps({"missing": missing, "noncompliant": noncompliant,
                          "ok": [r["path"] for r in ok],
                          "compliance_rate": round(rate, 1),
                          "stale_content": stale_content,
                          "cross_host_source_missing": cross_host,
                          "cross_host_degraded": cross_degraded,
                          "empty_fields": empty_fields,
                          "cross_dep_undeclared": cross_dep,
                          "rot_suspect": rot_suspect,
                          "snapshot_skipped": snapshot_skipped},
                         ensure_ascii=False, indent=2)
    else:
        L = []
        L.append("=== handoff_lint %s @%s ===" % (time.strftime("%F %T"), os.uname().nodename))
        L.append("HANDOFF 共 %d 份 | 合规 %d | 不合规 %d | 合规率 %.1f%%"
                 % (total, len(ok), len(noncompliant), rate))
        L.append("缺失 %d 处(其中 P0 %d 处)" % (len(missing), len(p0_missing)))
        if snapshot_skipped:
            L.append("冻结副本已排除 %d 份(快照区或有终态回执的只读证据包,不算活工作区):"
                     % len(snapshot_skipped))
            for w in snapshot_skipped[:5]:
                L.append("    - " + w)
            if len(snapshot_skipped) > 5:
                L.append("    ...另 %d 份" % (len(snapshot_skipped) - 5))
        if missing:
            L.append("--- 缺 HANDOFF.md ---")
            for m in sorted(missing, key=lambda x: x["priority"]):
                L.append("  [%s] %s  <= %s" % (m["priority"], m["path"], m["evidence"]))
        if noncompliant:
            L.append("--- 不合规 ---")
            for r in noncompliant:
                L.append("  [%s] %s" % (r["priority"], r["path"]))
                for d in r["defects"]:
                    L.append("        - " + d)
        L.append("--- STALE_CONTENT(独立等级,不计入合规率/退出码;阈值 %dd) ---"
                 % STALE_CONTENT_DAYS)
        if stale_content:
            for sc in stale_content:
                L.append("  %s  漂移%.1fd(内容最新 %s / 日志末条 %s)"
                         % (sc["path"], sc["drift_days"], sc["dir_latest"], sc["last_log_date"]))
        else:
            L.append("  (无)")
        if cross_degraded:
            L.append("--- CROSS_HOST_SOURCE_MISSING(独立等级):对侧不可达,本轮跳过 ---")
        else:
            L.append("--- CROSS_HOST_SOURCE_MISSING(独立等级,不计入合规率/退出码) ---")
            if cross_host:
                for ch in cross_host:
                    L.append("  %s  <= 两侧 HANDOFF.md 均未声明数据主源" % ch["path"])
            else:
                L.append("  (无)")
        # EMPTY_FIELD(<date> 新增):独立等级,不计入合规率/退出码
        # 字段集 = {这是什么,产线,做到哪,下一道门};卡点/「无」占位/absent 不进
        L.append("--- EMPTY_FIELD(独立等级,不计入合规率/退出码;新建区宽限30min;字段=%s) ---"
                 % "/".join(EMPTY_FIELDS))
        if empty_fields:
            for ef in empty_fields:
                L.append("  %s  <= 空字段: %s"
                         % (ef["path"], ", ".join(ef["fields"])))
        else:
            L.append("  (无)")
        # CROSS_DEP_UNDECLARED(<date> 新增):独立等级,不计入合规率/退出码
        L.append("--- CROSS_DEP_UNDECLARED(独立等级,不计入合规率/退出码) ---")
        if cross_dep:
            for cd in cross_dep:
                L.append("  %s  <= 正文提到但未声明的外部工作区: %s"
                         % (cd["path"], ", ".join(cd["deps"])))
            L.append("    修法:在「当前态」块加一行 `- 依赖: <路径1>, <路径2>`"
                     "(本区读它们的产物)或 `- 被依赖: <路径>`(它们读本区产物)")
        else:
            L.append("  (无)")
        # ROT_SUSPECT(<date> 新增):独立等级,不计入合规率/退出码;不看 mtime
        L.append("--- ROT_SUSPECT(独立等级,不计入合规率/退出码;判据不看 mtime) ---")
        if rot_suspect:
            for rt in rot_suspect:
                bits = []
                if rt["dead_paths"]:
                    bits.append("声称路径已不存在 %d 条(%s)"
                                % (len(rt["dead_paths"]), rt["dead_paths"][0]))
                if rt["dead_ports"]:
                    bits.append("声称本机端口无人监听: " + ", ".join(rt["dead_ports"]))
                if rt["done_gates"]:
                    bits.append("下一道门指向已完成任务: " + ", ".join(rt["done_gates"]))
                L.append("  %s  <= %s" % (rt["path"], "; ".join(bits)))
        else:
            L.append("  (无)")
        out = "\n".join(L)

    if not (args.quiet and not missing and not noncompliant):
        print(out)
    if args.log:
        os.makedirs(LOGDIR, exist_ok=True)
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(out + "\n")

    if args.push or args.push_force:
        sent, why = push_alert(missing, noncompliant, rate, total, force=args.push_force)
        msg = "[push] %s: %s" % ("已推送" if sent else "未推送", why)
        if not args.quiet or sent:
            print(msg)
        if args.log:
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

        # STALE_CONTENT / 跨机主源缺失 / EMPTY_FIELD:独立 Nag 实例,沿用现有告警出口(agent_nag),
        # 不新造推送通道,也不与上面的 P0 push_alert 状态账混在一起。
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from agent_nag import Nag
            issues2 = {}
            for sc in stale_content:
                issues2["STALE|%s" % sc["path"]] = (
                    "内容漂移%.1fd未记录: %s(日志末条%s)"
                    % (sc["drift_days"], sc["path"], sc["last_log_date"]))
            if not cross_degraded:
                for ch in cross_host:
                    issues2["CROSSHOST|%s" % ch["path"]] = (
                        "双机同名工作区缺主源声明: %s" % ch["path"])
            for ef in empty_fields:
                issues2["EMPTY|%s" % ef["path"]] = (
                    "当前态块真空字段: %s" % ", ".join(ef["fields"]))
            for cd in cross_dep:
                issues2["CROSSDEP|%s" % cd["path"]] = (
                    "跨区依赖未声明: %s 依赖 %s" % (cd["path"], ", ".join(cd["deps"][:3])))
            for rt in rot_suspect:
                issues2["ROT|%s" % rt["path"]] = (
                    "通稿断言已失效: %s(死路径%d/死端口%d/门已过%d)"
                    % (rt["path"], len(rt["dead_paths"]), len(rt["dead_ports"]),
                       len(rt["done_gates"])))
            nag = Nag("handoff_health")
            sent2, why2 = nag.report(
                issues2, title="HANDOFF 内容健康",
                summary="STALE_CONTENT %d 项 / 跨机主源缺失 %d 项 / EMPTY_FIELD %d 项 / "
                        "CROSS_DEP %d 项 / ROT_SUSPECT %d 项%s"
                        % (len(stale_content), len(cross_host), len(empty_fields),
                           len(cross_dep), len(rot_suspect),
                           "(跨机检查本轮跳过)" if cross_degraded else ""),
                all_clear="✅ STALE_CONTENT / 跨机主源声明 / EMPTY_FIELD / CROSS_DEP / ROT_SUSPECT 均清零",
                force=args.push_force)
            msg2 = "[push:health] %s: %s" % ("已推送" if sent2 else "未推送", why2)
        except Exception as e:
            msg2 = "[push:health] 异常,未推送: %s" % e
        if not args.quiet or "已推送" in msg2:
            print(msg2)
        if args.log:
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(msg2 + "\n")

    if p0_missing or any(r["priority"] == "P0" for r in noncompliant):
        return 1
    if missing or noncompliant:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        sys.stderr.write("handoff_lint ERROR: %s\n" % e)
        sys.exit(3)
