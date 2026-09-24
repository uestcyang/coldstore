#!/usr/bin/env python3
"""Workspace Pager state machine used by the existing ``ws`` command.

The pager is a control-plane database, not a FUSE filesystem.  It records
logical access events (``ws show``/``ws page enter``), leases, cloud coverage,
and archive snapshot verification. Eviction requires the current cloud-confirmed
head, an unchanged snapshot and all runtime safety checks; download-back testing
is not an eviction prerequisite. Capacity requests change scheduling only.
"""

from __future__ import annotations

import csv
import fcntl
import hashlib
import json
import gzip
import os
import platform
import socket
import re
import shutil
import shlex
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


HOME = Path.home()
STATE_DB = HOME / ".coldstore" / "state" / "workspace_pages.db"
def _default_policy_path() -> Path:
    env = os.environ.get("COLDSTORE_PAGER_POLICY")
    if env:
        return Path(env).expanduser()
    user = HOME / ".coldstore" / "etc" / "workspace_pager_policy.json"
    if user.exists():
        return user
    return Path(__file__).resolve().parent.parent / "config" / "workspace_pager_policy.example.json"


DEFAULT_POLICY = _default_policy_path()
# 隔离池告急线。PAGER_ISOLATION_LOW 此前只有 warn 一级,而 Widget 的 ack 机制
# 靠"warn 恶化成 err 就自动失效"来保证用户裁决的静音不掩盖真故障
# (widget_alert_policy.py 的 _ack_covers)。只有一级 = 那层保护对这条码是空的:
# 一旦被 ack,隔离池从 warn 线一路跌到写满都不会再上屏。补上 err 形态后,
# 静音只压住"接近上限"的常态噪音,真到快写不进去时仍然穿透。
# 可选键:旧策略文件缺省即用此值。不加进 load_policy 的必填集合——改必填会让
# 现存策略文件当场 fail-closed 拒绝加载。
DEFAULT_ISOLATION_ERR_FREE_RATIO = 0.03
CLOUD_WORKSPACE = (
    Path("/Users/user/.coldstore/archive")
    if platform.system() == "Darwin"
    else Path("/home/user/.coldstore/archive")
)
CLOUD_CATALOG = CLOUD_WORKSPACE / "cloud_asset_catalog.jsonl"
RESTORE_TESTS = CLOUD_WORKSPACE / "cloud_asset_restore_tests.tsv"
RESTORE_TOOL = CLOUD_WORKSPACE / "cloud_asset_restore.py"
# Operator policy "trust-the-cloud": the
# restore-verification ledger/alert/drain is gone.  Cloud confirmation of the
# current archive head plus an unchanged archive-time snapshot is the eviction
# proof; nothing is downloaded back to earn the right to delete a local copy.
# Incident note: root cause of every automated restore test failing since
# <date> with REFUSE_WEBSOCKET_CLIENT_MISSING: restore_asset() spawned RESTORE_TOOL
# through its `#!/usr/bin/env python3` shebang, so the interpreter was whatever
# `python3` the *caller's* PATH resolved.  Under the agent cron gateway PATH
# starts with agent/venv/bin (Python 3.11, no `websocket-client`), while
# an interactive shell resolves homebrew 3.14 / miniconda 3.13 which have it --
# same command, pass by hand, fail under cron.  The interpreter is now chosen
# by capability (can it `import websocket`), never by PATH.  Order: explicit
# override, the interpreter cloud_asset_evict_once.py already pins for the very
# same tool, then the current one, then well-known system pythons.
RESTORE_PYTHON_CANDIDATES = (
    os.environ.get("PAGER_RESTORE_PYTHON") or "",
    "/Users/user/miniconda3/bin/python",
    sys.executable or "",
    "/opt/homebrew/bin/python3",
    "/usr/local/bin/python3",
    "/usr/bin/python3",
)
_RESTORE_PYTHON: str | None = None


def _probe_websocket(python: str) -> bool:
    try:
        proc = subprocess.run([python, "-c", "import websocket"],
                              text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def restore_python(candidates: Iterable[str] = RESTORE_PYTHON_CANDIDATES,
                   probe=None) -> str:
    """First candidate interpreter that can import websocket-client; fail closed."""
    global _RESTORE_PYTHON
    cached = probe is None
    if cached and _RESTORE_PYTHON:
        return _RESTORE_PYTHON
    check = probe or _probe_websocket
    tried = []
    for cand in candidates:
        if not cand:
            continue
        if not Path(cand).is_file():
            tried.append(cand + ":missing")
            continue
        if check(cand):
            if cached:
                _RESTORE_PYTHON = cand
            return cand
        tried.append(cand + ":no-websocket-client")
    raise PagerRefused("REFUSE_WEBSOCKET_CLIENT_MISSING no interpreter with "
                       "websocket-client; tried " + ",".join(tried))


CLOUD_MANIFEST_DIR = CLOUD_WORKSPACE / "manifests"
PAGE_CACHE = HOME / ".coldstore" / "page_cache"
VALID_STATES = {"HOT", "WARM", "COLD", "PINNED", "ISOLATED"}
VALID_STORAGE_POOLS = {"MANAGED", "ISOLATED", "EXTERNAL"}
VALID_ANNOTATION_STATES = {"CURRENT", "SEMANTIC_STALE", "SYNC_FAILED"}
VALID_REDUNDANCY_CLASSES = {
    "UNCLASSIFIED", "REGENERABLE", "CLOUD_ACCEPTED", "VALUABLE", "IRREPLACEABLE",
}
MIN_INDEPENDENT_COPIES = {
    "UNCLASSIFIED": None,
    "REGENERABLE": 1,
    "CLOUD_ACCEPTED": 1,
    "VALUABLE": 2,
    "IRREPLACEABLE": 3,
}
# <date>: read-only engines and model weights.  The tree liveness probe
# answers with ``find -newermt`` -- *modification* time -- and weights are never
# modified, only read.  So an engine used by every single render task still reads
# as stone cold, gets evicted to the cloud, and the next task faults 19.4GB back
# in through the Mac.  That thrash is what filled the Mac to zero free bytes and
# left every tool on the host unable to create a temp file.
#
# Pinning does not force a restore: a pinned COLD asset stays in the cloud until
# something actually needs it.  It only stops the asset from bouncing back out
# again the moment it lands.
# Deployment-specific pin lists live in a config file, not in code.  Resolution:
# $COLDSTORE_PAGER_PATHS -> <repo>/config/pager_paths.json -> config/pager_paths.example.json.
# Unreadable/invalid file == empty lists (a pin list only ever *protects*, so empty is safe).
def _load_pager_paths():
    cands = [os.environ.get("COLDSTORE_PAGER_PATHS"),
             str(Path(__file__).resolve().parent.parent / "config" / "pager_paths.json"),
             str(Path(__file__).resolve().parent.parent / "config" / "pager_paths.example.json")]
    for c in cands:
        if not c:
            continue
        try:
            doc = json.loads(Path(c).read_text(encoding="utf-8"))
            ro = {os.path.expanduser(p) for p in doc.get("read_only_engine_paths", [])}
            ap = {os.path.expanduser(p) for p in doc.get("auto_pin_paths", [])}
            return ro, ap
        except (OSError, ValueError, AttributeError):
            continue
    return set(), set()


READ_ONLY_ENGINE_PATHS, _CONFIG_AUTO_PIN = _load_pager_paths()
AUTO_PIN_PATHS = {str(HOME / ".coldstore"), str(CLOUD_WORKSPACE)} | _CONFIG_AUTO_PIN | READ_ONLY_ENGINE_PATHS

# Incident note: 上面两条新钉是同一类漏洞的两个实例, 所以再给它一个**声明式**
# 登记口, 免得下一个合同 owner 还得来改这份共享代码(改不动就不改, 然后又丢一次)。
# 文件只追加、只读; 读不到或格式不对就当空 —— 硬编码那份是地板, 这里是扩展位。
CONTRACT_PIN_FILE = HOME / ".coldstore" / "state" / "contract_pinned_paths.json"


def _contract_pinned_paths() -> set[str]:
    """活合同点名的证据根/工作区:按"被谁引用"钉住, 而不是按"多久没写"。

    分页器的冷热判据是写入新近度, 对这一类路径系统性失灵:它们**读热写冷**
    —— 一周写一次、每拍读一次。被归档清掉之后, 引用方(维护探针 / 初中 resume)
    才在下游报一个看上去毫不相干的错。
    """
    try:
        raw = json.loads(CONTRACT_PIN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    rows = raw.get("paths") if isinstance(raw, dict) else raw
    out: set[str] = set()
    for row in rows or []:
        path = row.get("path") if isinstance(row, dict) else row
        if isinstance(path, str) and path.startswith("/"):
            out.add(os.path.normpath(path))
    return out


AUTO_PIN_PATHS |= _contract_pinned_paths()

PAGES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS pages(
  workspace_key TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('HOT','WARM','COLD','PINNED','ISOLATED')),
  storage_pool TEXT NOT NULL DEFAULT 'MANAGED'
    CHECK(storage_pool IN ('MANAGED','ISOLATED','EXTERNAL')),
  pinned INTEGER NOT NULL DEFAULT 0,
  local_present INTEGER NOT NULL DEFAULT -1,
  dirty INTEGER NOT NULL DEFAULT 1,
  cloud_asset_id TEXT,
  cloud_verified INTEGER NOT NULL DEFAULT 0,
  restore_verified INTEGER NOT NULL DEFAULT 0,
  snapshot_verified INTEGER NOT NULL DEFAULT 0,
  redundancy_class TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
  independent_copies INTEGER NOT NULL DEFAULT 0,
  classification_reason TEXT,
  classified_at REAL,
  size_bytes INTEGER,
  last_access REAL,
  last_write REAL,
  archive_epoch REAL,
  lease_until REAL,
  access_count INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  content_fingerprint TEXT,
  semantic_revision INTEGER NOT NULL DEFAULT 0,
  annotation_status TEXT NOT NULL DEFAULT 'CURRENT'
    CHECK(annotation_status IN ('CURRENT','SEMANTIC_STALE','SYNC_FAILED')),
  semantic_summary TEXT,
  semantic_keywords_json TEXT NOT NULL DEFAULT '[]',
  annotated_by TEXT,
  annotated_at REAL,
  index_synced_at REAL,
  semantic_stale_task TEXT,
  semantic_stale_at REAL,
  semantic_pending_files_json TEXT NOT NULL DEFAULT '[]',
  updated_at REAL NOT NULL
)
"""


class PagerRefused(RuntimeError):
    pass


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, traceback):
        try:
            return super().__exit__(exc_type, exc, traceback)
        finally:
            self.close()


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PagerRefused(f"REFUSE_PAGER_POLICY_UNREADABLE {path}: {exc}") from exc
    if raw.get("schema_version") != 2:
        raise PagerRefused(
            f"REFUSE_PAGER_POLICY_SCHEMA expected=2 got={raw.get('schema_version')}"
        )
    required = {
        "managed_mount", "isolation_mount", "low_free_ratio", "stop_free_ratio",
        "hot_ratio", "warm_ratio", "isolation_warn_free_ratio",
        "evict_enabled", "pool_migration_state",
    }
    missing = sorted(required - set(raw))
    if missing:
        raise PagerRefused("REFUSE_PAGER_POLICY_MISSING " + ",".join(missing))
    low = float(raw["low_free_ratio"])
    stop = float(raw["stop_free_ratio"])
    hot = float(raw["hot_ratio"])
    warm = float(raw["warm_ratio"])
    if not (0 < low < stop < 1):
        raise PagerRefused("REFUSE_PAGER_WATERMARK_ORDER")
    iso_warn = float(raw["isolation_warn_free_ratio"])
    iso_err = float(raw.get("isolation_err_free_ratio",
                            DEFAULT_ISOLATION_ERR_FREE_RATIO))
    if not (0 < iso_err < iso_warn):
        raise PagerRefused(
            "REFUSE_PAGER_ISOLATION_THRESHOLD_ORDER err=%.4f warn=%.4f"
            % (iso_err, iso_warn))
    raw["isolation_err_free_ratio"] = iso_err
    if abs((hot + warm) - 1.0) > 1e-9 or hot <= 0 or warm <= 0:
        raise PagerRefused("REFUSE_PAGER_TEMPERATURE_RATIO")
    if not isinstance(raw["evict_enabled"], bool):
        raise PagerRefused("REFUSE_PAGER_EVICTION_POLICY_TYPE")
    migration_state = str(raw["pool_migration_state"])
    if migration_state not in {"DRAINING", "COMPLETE"}:
        raise PagerRefused(
            f"REFUSE_PAGER_MIGRATION_STATE state={migration_state}"
        )
    if raw["evict_enabled"] and migration_state != "COMPLETE":
        raise PagerRefused("REFUSE_PAGER_EVICTION_BEFORE_MIGRATION_COMPLETE")
    for key in ("managed_mount", "isolation_mount"):
        value = os.path.normpath(str(raw[key]))
        if not os.path.isabs(value):
            raise PagerRefused(f"REFUSE_PAGER_MOUNT_NOT_ABSOLUTE {key}={value}")
        raw[key] = value
    raw["isolation_exceptions"] = [
        os.path.normpath(str(x)) for x in raw.get("isolation_exceptions", [])
    ]
    return raw


def _path_is_at_or_below(path: str, root: str) -> bool:
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _load_semantic_rows(path: Path, max_bytes: int = 16 * 1024 * 1024) -> dict[str, dict[str, Any]]:
    """Read and validate one exported semantic JSONL file.

    Semantic exports cross the Mac/hostb trust boundary.  Invalid or conflicting
    rows must fail closed before the authoritative file is replaced.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PagerRefused(f"REFUSE_SEMANTIC_EXPORT_UNREADABLE {path}: {exc}") from exc
    if size > max_bytes:
        raise PagerRefused(
            f"REFUSE_SEMANTIC_EXPORT_TOO_LARGE path={path} bytes={size} max={max_bytes}"
        )
    rows: dict[str, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PagerRefused(f"REFUSE_SEMANTIC_EXPORT_UNREADABLE {path}: {exc}") from exc
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_JSON path={path} line={line_no}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_ROW path={path} line={line_no}"
            )
        host, raw_path = row.get("host"), row.get("path")
        if host not in {"mac", "hostb"} or not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_ID path={path} line={line_no}"
            )
        key = WorkspacePager.key(host, raw_path)
        if row.get("workspace_key") != key:
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_KEY path={path} line={line_no} expected={key}"
            )
        revision = row.get("semantic_revision")
        fingerprint = row.get("content_fingerprint")
        if (not isinstance(revision, int) or isinstance(revision, bool) or revision < 1 or
                not isinstance(fingerprint, str) or
                re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_REVISION path={path} line={line_no}"
            )
        summary = row.get("summary")
        keywords_json = row.get("keywords_json")
        if not isinstance(summary, str) or not summary.strip() or not isinstance(keywords_json, str):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_CONTENT path={path} line={line_no}"
            )
        try:
            keywords = json.loads(keywords_json)
        except json.JSONDecodeError as exc:
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_KEYWORDS path={path} line={line_no}"
            ) from exc
        if not isinstance(keywords, list) or any(not isinstance(x, str) for x in keywords):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_KEYWORDS path={path} line={line_no}"
            )
        previous = rows.get(key)
        if previous is not None and previous != row:
            raise PagerRefused(
                f"REFUSE_SEMANTIC_EXPORT_DUPLICATE_CONFLICT key={key} path={path}"
            )
        rows[key] = row
    return rows


def merge_semantic_exports(authority: Path, incoming: Path) -> dict[str, int]:
    """Merge a host export into the Mac authority by monotonic revision.

    Equal revisions must describe the same annotation.  A stale peer can never
    overwrite a newer authority row.  The caller owns the cross-process lock so
    it can keep the subsequent catalog/encrypted-state sync in the same critical
    section.
    """
    authority, incoming = Path(authority), Path(incoming)
    current = _load_semantic_rows(authority) if authority.is_file() else {}
    offered = _load_semantic_rows(incoming)
    inserted = advanced = stale = identical = 0
    for key, row in offered.items():
        old = current.get(key)
        if old is None:
            current[key] = row
            inserted += 1
            continue
        new_revision = int(row["semantic_revision"])
        old_revision = int(old["semantic_revision"])
        if new_revision < old_revision:
            stale += 1
            continue
        if new_revision > old_revision:
            current[key] = row
            advanced += 1
            continue
        core_fields = (
            "content_fingerprint", "summary", "keywords_json", "annotated_by", "annotated_at",
        )
        if any(old.get(field) != row.get(field) for field in core_fields):
            raise PagerRefused(
                f"REFUSE_SEMANTIC_REVISION_CONFLICT key={key} revision={new_revision}"
            )
        # Mapping and sync timestamps are transport metadata, not annotation
        # identity.  Keep the most informative/idempotently newest copy.
        merged = dict(old)
        old_asset, new_asset = old.get("cloud_asset_id"), row.get("cloud_asset_id")
        if old_asset and new_asset and old_asset != new_asset:
            raise PagerRefused(
                f"REFUSE_SEMANTIC_ASSET_CONFLICT key={key} revision={new_revision}"
            )
        merged["cloud_asset_id"] = old_asset or new_asset
        merged["index_synced_at"] = max(
            float(old.get("index_synced_at") or 0), float(row.get("index_synced_at") or 0)
        ) or None
        current[key] = merged
        identical += 1
    authority.parent.mkdir(parents=True, exist_ok=True)
    tmp = authority.with_name(authority.name + f".tmp.{os.getpid()}")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            for key in sorted(current):
                handle.write(json.dumps(current[key], ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, authority)
    finally:
        tmp.unlink(missing_ok=True)
    return {
        "rows": len(current), "inserted": inserted, "advanced": advanced,
        "stale": stale, "identical": identical,
    }


def should_auto_pin(path: str) -> bool:
    """Exact match for the historical roots; sub-tree match for engines.

    The weights that actually get indexed are leaves, not roots -- the page table
    carries ``engine-e/checkpoints/gpt.pth`` and friends, never ``engine-e``
    itself.  An exact-match-only rule would therefore pin nothing that matters
    for the very case this list was added for.
    """
    norm = os.path.normpath(path)
    if norm in {os.path.normpath(p) for p in AUTO_PIN_PATHS}:
        return True
    return any(_path_is_at_or_below(norm, os.path.normpath(root))
               for root in READ_ONLY_ENGINE_PATHS)


def auto_pin_applies(path: str, local_present: int | None) -> bool:
    """Auto-pin protects a *local* copy; it says nothing about cloud-only rows.

    Pinning a row whose bytes live only in the vault contradicts ``plan()``,
    which classifies ``local_present == 0 and cloud_verified`` as KEEP_COLD, and
    would make the tree un-evictable the moment it is faulted back in.  The seven
    Mac tts-engine weights deleted on <date> sat exactly in that state.
    Unknown presence (-1) fails safe: do not pin what we cannot see.
    """
    return local_present == 1 and should_auto_pin(path)


def is_pager_scratch(path: str) -> bool:
    """True for the pager's own restore staging, on any host.

    <date>: three ``.coldstore/page_cache/restore-hostb-wan-vace-*/engine-a``
    staging trees were indexed as HOT/WARM workspaces, because a restored tree
    carries the original workspace's HANDOFF.md and the graph indexer only looks
    for that file.  So the pager was tracking -- and would eventually have
    archived back to the cloud -- its own scratch copies of an asset that is
    already in the cloud.  The rows also outlived the directories, leaving the
    table asserting local_present=1 for paths that no longer exist.

    Host-agnostic on purpose: ``HOME`` differs per host, but the ``.coldstore``
    layout does not.
    """
    parts = os.path.normpath(path).split(os.sep)
    return any(parts[i] == ".coldstore" and parts[i + 1] == "page_cache"
               for i in range(len(parts) - 1))


def storage_pool_for(host: str, path: str, policy: dict[str, Any]) -> str:
    """Return the physical pool.  The hostb mount boundary is authoritative."""
    if host != "hostb":
        return "EXTERNAL"
    path = os.path.normpath(path)
    if _path_is_at_or_below(path, policy["isolation_mount"]):
        for exception in policy.get("isolation_exceptions", []):
            if _path_is_at_or_below(path, exception):
                return "MANAGED"
        return "ISOLATED"
    return "MANAGED"


def _content_entry(path: Path) -> dict[str, Any]:
    """Hash real bytes for one changed path; missing paths become tombstones."""
    raw = str(path)
    if not os.path.lexists(raw):
        return {"path": raw, "kind": "missing", "sha256": hashlib.sha256(b"MISSING").hexdigest()}
    if path.is_symlink():
        target = os.readlink(path)
        return {"path": raw, "kind": "symlink", "target": target,
                "sha256": hashlib.sha256(("L\0" + target).encode()).hexdigest()}
    if path.is_file():
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(block)
        return {"path": raw, "kind": "file", "bytes": path.stat().st_size,
                "sha256": digest.hexdigest()}
    if path.is_dir():
        digest = hashlib.sha256()
        entries = files = total = 0
        for root, dirs, names in os.walk(path, topdown=True, followlinks=False):
            dirs.sort(); names.sort()
            base = Path(root)
            for name in dirs + names:
                full = base / name
                rel = str(full.relative_to(path))
                if full.is_symlink():
                    row = ["L", rel, os.readlink(full)]
                elif full.is_dir():
                    row = ["D", rel]
                elif full.is_file():
                    child = _content_entry(full)
                    files += 1
                    total += int(child.get("bytes") or 0)
                    row = ["F", rel, child["bytes"], child["sha256"]]
                else:
                    row = ["O", rel]
                digest.update(json.dumps(
                    row, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8") + b"\n")
                entries += 1
        return {"path": raw, "kind": "directory", "entries": entries,
                "files": files, "bytes": total, "sha256": digest.hexdigest()}
    raise PagerRefused(f"REFUSE_UNSUPPORTED_CONTENT_PATH {path}")


def content_fingerprint(path: str | os.PathLike[str]) -> dict[str, Any]:
    return _content_entry(Path(path))


def _epoch(value: Any) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (ValueError, TypeError):
        return None


CANONICAL_HOSTS = ("mac", "hostb")


def _self_host() -> str:
    """This machine's canonical pager name (same rule as CLOUD_WORKSPACE)."""
    return "mac" if platform.system() == "Darwin" else "hostb"


def _host_name(value: str | None) -> str:
    low = (value or "").strip().lower()
    if low in {"mac", "host-a", "host-a"}:
        return "mac"
    if low in {"hostb", "linux"}:
        return "hostb"
    # A real hostname must fold back.  ``storage_pool_for`` only recognises
    # "hostb"; anything else lands in EXTERNAL, i.e. outside paging entirely, and
    # splits into a second row alongside the canonical one.  Two such rows were
    # measured on the hostb on <date>, written straight through ``touch``.
    if low:
        me = socket.gethostname().strip().lower()
        if low == me or low == me.split(".")[0]:
            return _self_host()
    return low or "unknown"


def load_assets(catalog_path: Path = CLOUD_CATALOG,
                restore_tests_path: Path = RESTORE_TESTS) -> list[dict[str, Any]]:
    passed = set()
    try:
        for line in restore_tests_path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) >= 4 and cols[3] == "PASS":
                passed.add(cols[0])
    except OSError:
        pass
    assets = []
    try:
        lines = catalog_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return assets
    for line in lines:
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            asset_id = str(raw["asset_id"])
            original = str(raw["original_path"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        cloud_verified = raw.get("cloud_state") == "confirmed"
        # restore_verified is informational only (<date>): a real page-in or a
        # manual ``ws page verify`` still records it, but it no longer gates
        # eviction or classification.  v3 rows may self-assert it when tagged.
        restore_verified = asset_id in passed or (
            raw.get("vault") == "v3" and raw.get("restore_verified") is True
        )
        snapshot_verified = bool(raw.get("snapshot_verified", False))
        fully_proven = cloud_verified and snapshot_verified
        item = dict(raw)
        item.update({
            "kind": "cloud_asset",
            "asset_id": asset_id,
            "original_path": original,
            "host": _host_name(str(raw.get("machine") or "")),
            "size_bytes": int(raw.get("size") or raw.get("size_bytes") or 0),
            "cloud_verified": cloud_verified,
            "restore_verified": restore_verified,
            "indexed_at_epoch": _epoch(raw.get("archived_at")),
            # Legacy catalog rows predate a content fingerprint contract.  Do
            # not infer one from size or cloud state.
            "snapshot_verified": snapshot_verified,
            "redundancy_class": str(
                raw.get("redundancy_class")
                or ("CLOUD_ACCEPTED" if fully_proven else "UNCLASSIFIED")
            ).upper(),
            "independent_copies": int(
                raw.get("independent_copies")
                if raw.get("independent_copies") is not None
                else (1 if fully_proven else 0)
            ),
            "classification_reason": raw.get("classification_reason") or (
                "user-approved Baidu cold-pool contract; cloud confirmed and archive snapshot proven"
                if fully_proven else None
            ),
            "classified_at_epoch": _epoch(raw.get("classified_at")) or (
                _epoch(raw.get("archived_at")) if fully_proven else None
            ),
            "content_fingerprint": raw.get("content_fingerprint"),
            "semantic_revision": int(raw.get("semantic_revision") or 0),
            "annotation_status": str(raw.get("annotation_status") or "CURRENT"),
            "semantic_summary": raw.get("semantic_summary") or raw.get("description"),
            "semantic_keywords_json": json.dumps(
                raw.get("semantic_keywords") or raw.get("keywords") or [],
                ensure_ascii=False, sort_keys=True,
            ),
            "annotated_by": raw.get("annotated_by"),
            "annotated_at": _epoch(raw.get("annotated_at")),
            "index_synced_at": _epoch(raw.get("index_synced_at")),
        })
        assets.append(item)
    assets.sort(key=lambda x: x["asset_id"])
    return assets


def asset_search(assets: Iterable[dict[str, Any]], keywords: Iterable[str],
                 limit: int = 10) -> list[tuple[int, dict[str, Any], list[str]]]:
    kws = [str(k).lower() for k in keywords if str(k).strip()]
    scored = []
    for asset in assets:
        fields = {
            "asset_id": 14,
            "label": 12,
            "original_path": 10,
            "description": 8,
            "keywords": 5,
        }
        score, matched = 0, []
        for kw in kws:
            got = False
            for name, weight in fields.items():
                value = asset.get(name, "")
                if isinstance(value, list):
                    value = " ".join(map(str, value))
                if kw in str(value).lower():
                    score += weight
                    got = True
            if got:
                matched.append(kw)
        if kws and len(matched) == len(kws):
            score += 20
        if score:
            scored.append((score, asset, matched))
    scored.sort(key=lambda x: (-x[0], x[1]["asset_id"]))
    return scored[:limit]


def disk_stats_from_sample(sample, policy, now=None):
    now = time.time() if now is None else now
    try:
        observed = sample['observed_at']
        if sample['host'] != 'hostb' or type(observed) not in (int, float) or not 0 <= now - observed <= 25:
            raise ValueError('stale or wrong-host disk sample')
        disks = sample['disks']
        mapped = {row['mount']: row for row in disks}
        if len(mapped) != len(disks):
            raise ValueError('duplicate disk sample')
        output = {}
        for pool, key in (('managed', 'managed_mount'), ('isolated', 'isolation_mount')):
            row = mapped[policy[key]]
            if not all(type(row[field]) is int and row[field] >= 0 for field in ('total', 'used', 'free')) or \
                    row['total'] <= 0 or row['used'] + row['free'] > row['total']:
                raise ValueError('invalid disk sizes')
            output[pool] = dict(row)
        return output
    except (KeyError, TypeError, ValueError) as error:
        raise PagerRefused('REFUSE_PAGER_DISK_SAMPLE_INVALID') from error


class WorkspacePager:
    def __init__(self, db_path: Path = STATE_DB,
                 manifest_dir: Path = CLOUD_MANIFEST_DIR,
                 policy_config: dict[str, Any] | None = None,
                 read_only: bool = False):
        self.db_path = Path(db_path)
        self.manifest_dir = Path(manifest_dir)
        self.policy = dict(policy_config) if policy_config is not None else load_policy()
        self.read_only = read_only
        if not self.read_only:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_schema()

    def connect(self) -> sqlite3.Connection:
        if self.read_only:
            conn = sqlite3.connect(self.db_path.resolve().as_uri() + '?mode=ro', uri=True,
                                   timeout=1, factory=_ClosingConnection)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA query_only=ON')
            return conn
        conn = sqlite3.connect(self.db_path, timeout=30, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.execute(PAGES_TABLE_SQL)
            conn.executescript(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS pages_host_path ON pages(host,path);
                CREATE TABLE IF NOT EXISTS events(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  at REAL NOT NULL,
                  workspace_key TEXT,
                  event TEXT NOT NULL,
                  reason TEXT,
                  metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS events_workspace_at ON events(workspace_key,at);
                CREATE TABLE IF NOT EXISTS asset_files(
                  source_path TEXT NOT NULL,
                  asset_id TEXT NOT NULL,
                  relative_path TEXT NOT NULL,
                  size_bytes INTEGER NOT NULL DEFAULT 0,
                  mtime_ns INTEGER,
                  PRIMARY KEY(source_path,relative_path)
                );
                CREATE INDEX IF NOT EXISTS asset_files_asset ON asset_files(asset_id);
                CREATE TABLE IF NOT EXISTS asset_file_sources(
                  source_path TEXT PRIMARY KEY,
                  mtime_ns INTEGER NOT NULL,
                  size_bytes INTEGER NOT NULL,
                  indexed_at REAL NOT NULL,
                  row_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pager_meta(
                  key TEXT PRIMARY KEY,
                  value_json TEXT NOT NULL,
                  updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS page_semantics(
                  workspace_key TEXT PRIMARY KEY,
                  summary TEXT NOT NULL,
                  keywords_json TEXT NOT NULL DEFAULT '[]',
                  semantic_revision INTEGER NOT NULL,
                  content_fingerprint TEXT NOT NULL,
                  annotated_by TEXT NOT NULL,
                  annotated_at REAL NOT NULL,
                  index_synced_at REAL NOT NULL
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS page_semantics_fts USING fts5(
                  workspace_key UNINDEXED, summary, keywords,
                  tokenize='trigram'
                );
                """
            )
            table_sql = str(conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='pages'"
            ).fetchone()[0])
            if "'ISOLATED'" not in table_sql:
                legacy = "pages_legacy_state_20260831"
                if conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (legacy,)
                ).fetchone():
                    raise PagerRefused(f"REFUSE_PAGER_LEGACY_TABLE_EXISTS {legacy}")
                conn.execute("DROP INDEX IF EXISTS pages_host_path")
                conn.execute(f"ALTER TABLE pages RENAME TO {legacy}")
                conn.execute(PAGES_TABLE_SQL)
                old_columns = {
                    row[1] for row in conn.execute(f"PRAGMA table_info({legacy})")
                }
                new_columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(pages)")
                }
                common = [
                    row[1] for row in conn.execute(f"PRAGMA table_info({legacy})")
                    if row[1] in new_columns
                ]
                if "workspace_key" not in old_columns or not common:
                    raise PagerRefused("REFUSE_PAGER_LEGACY_SCHEMA_UNRECOGNIZED")
                cols = ",".join(common)
                conn.execute(f"INSERT INTO pages({cols}) SELECT {cols} FROM {legacy}")
                conn.execute(f"DROP TABLE {legacy}")
                conn.execute("CREATE UNIQUE INDEX pages_host_path ON pages(host,path)")
            columns = {r[1] for r in conn.execute("PRAGMA table_info(pages)")}
            migrations = {
                "redundancy_class":
                    "ALTER TABLE pages ADD COLUMN redundancy_class TEXT NOT NULL DEFAULT 'UNCLASSIFIED'",
                "independent_copies":
                    "ALTER TABLE pages ADD COLUMN independent_copies INTEGER NOT NULL DEFAULT 0",
                "classification_reason":
                    "ALTER TABLE pages ADD COLUMN classification_reason TEXT",
                "classified_at":
                    "ALTER TABLE pages ADD COLUMN classified_at REAL",
                "storage_pool":
                    "ALTER TABLE pages ADD COLUMN storage_pool TEXT NOT NULL DEFAULT 'MANAGED'",
                "content_fingerprint":
                    "ALTER TABLE pages ADD COLUMN content_fingerprint TEXT",
                "semantic_revision":
                    "ALTER TABLE pages ADD COLUMN semantic_revision INTEGER NOT NULL DEFAULT 0",
                "annotation_status":
                    "ALTER TABLE pages ADD COLUMN annotation_status TEXT NOT NULL DEFAULT 'CURRENT'",
                "semantic_summary":
                    "ALTER TABLE pages ADD COLUMN semantic_summary TEXT",
                "semantic_keywords_json":
                    "ALTER TABLE pages ADD COLUMN semantic_keywords_json TEXT NOT NULL DEFAULT '[]'",
                "annotated_by":
                    "ALTER TABLE pages ADD COLUMN annotated_by TEXT",
                "annotated_at":
                    "ALTER TABLE pages ADD COLUMN annotated_at REAL",
                "index_synced_at":
                    "ALTER TABLE pages ADD COLUMN index_synced_at REAL",
                "semantic_stale_task":
                    "ALTER TABLE pages ADD COLUMN semantic_stale_task TEXT",
                "semantic_stale_at":
                    "ALTER TABLE pages ADD COLUMN semantic_stale_at REAL",
                "semantic_pending_files_json":
                    "ALTER TABLE pages ADD COLUMN semantic_pending_files_json TEXT NOT NULL DEFAULT '[]'",
                # <date> liveness gate.  ``last_access`` is seeded from HANDOFF.md's
                # mtime at registration and then frozen (sync() copies old["last_access"]
                # forward verbatim), so a workspace whose HANDOFF is stale looks ancient
                # no matter how much data churns inside it.  Observed on hostb:
                # agent_roles (70GB, 123356 files modified in 7d) and
                # .coldstore/dispatch (7.4GB, 10812 files in 7d) were both classified
                # ARCHIVE_CANDIDATE.  These columns cache a cheap short-circuit probe of
                # real filesystem recency so plan() can refuse to cool a live tree.
                "tree_recent":
                    "ALTER TABLE pages ADD COLUMN tree_recent INTEGER",
                "tree_probed_at":
                    "ALTER TABLE pages ADD COLUMN tree_probed_at REAL",
                "tree_probe_days":
                    "ALTER TABLE pages ADD COLUMN tree_probe_days REAL",
            }
            for name, statement in migrations.items():
                if name not in columns:
                    conn.execute(statement)
            semantic_fts_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='page_semantics_fts'"
            ).fetchone()
            if semantic_fts_sql and "trigram" not in str(semantic_fts_sql[0]):
                conn.execute("DROP TABLE page_semantics_fts")
                conn.execute(
                    "CREATE VIRTUAL TABLE page_semantics_fts USING fts5("
                    "workspace_key UNINDEXED,summary,keywords,tokenize='trigram')"
                )
                conn.execute(
                    "INSERT INTO page_semantics_fts(workspace_key,summary,keywords) "
                    "SELECT workspace_key,summary,keywords_json FROM page_semantics"
                )

    @staticmethod
    def _asset_fts_exists(conn: sqlite3.Connection) -> bool:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='asset_files_fts'"
        ).fetchone() is not None

    def _ensure_asset_fts(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Create/backfill the derived FTS index during explicit sync only.

        ``WorkspacePager()`` and ``search_asset_files`` deliberately do not
        migrate or rebuild this table.  A stale/missing FTS index therefore
        cannot turn a read query into a 570k-row maintenance pass.
        """
        created = not self._asset_fts_exists(conn)
        conn.execute(
            """CREATE VIRTUAL TABLE IF NOT EXISTS asset_files_fts USING fts5(
               source_path UNINDEXED, asset_id UNINDEXED, relative_path,
               tokenize='trigram')"""
        )
        base_rows = int(conn.execute("SELECT count(*) FROM asset_files").fetchone()[0])
        fts_rows = int(conn.execute("SELECT count(*) FROM asset_files_fts").fetchone()[0])
        rebuilt = 0
        if created or base_rows != fts_rows:
            conn.execute("DELETE FROM asset_files_fts")
            conn.execute(
                "INSERT INTO asset_files_fts(source_path,asset_id,relative_path) "
                "SELECT source_path,asset_id,relative_path FROM asset_files"
            )
            rebuilt = base_rows
        return {"fts_created": int(created), "fts_rebuilt_files": rebuilt}

    def _sync_asset_files(self, conn: sqlite3.Connection) -> dict[str, int]:
        changed = imported = 0
        fts_state = self._ensure_asset_fts(conn)
        if not self.manifest_dir.is_dir():
            fts_rows = int(conn.execute("SELECT count(*) FROM asset_files_fts").fetchone()[0])
            return {"changed_sources": 0, "imported_files": 0,
                    "fts_files": fts_rows, **fts_state}
        current_paths = set()
        for source in sorted(self.manifest_dir.glob("*.jsonl.gz")):
            current_paths.add(str(source))
            st = source.stat()
            old = conn.execute(
                "SELECT mtime_ns,size_bytes FROM asset_file_sources WHERE source_path=?",
                (str(source),),
            ).fetchone()
            if old and old[0] == st.st_mtime_ns and old[1] == st.st_size:
                continue
            changed += 1
            conn.execute("DELETE FROM asset_files WHERE source_path=?", (str(source),))
            conn.execute("DELETE FROM asset_files_fts WHERE source_path=?", (str(source),))
            batch, count = [], 0
            with gzip.open(source, "rt", encoding="utf-8", errors="strict") as f:
                for line in f:
                    row = json.loads(line)
                    batch.append((
                        str(source), str(row["asset_id"]), str(row["relative_path"]),
                        int(row.get("size") or 0),
                        int(row["mtime_ns"]) if row.get("mtime_ns") is not None else None,
                    ))
                    if len(batch) >= 5000:
                        conn.executemany(
                            "INSERT INTO asset_files(source_path,asset_id,relative_path,size_bytes,mtime_ns) "
                            "VALUES(?,?,?,?,?)", batch)
                        conn.executemany(
                            "INSERT INTO asset_files_fts(source_path,asset_id,relative_path) "
                            "VALUES(?,?,?)", [(x[0], x[1], x[2]) for x in batch])
                        count += len(batch)
                        batch = []
            if batch:
                conn.executemany(
                    "INSERT INTO asset_files(source_path,asset_id,relative_path,size_bytes,mtime_ns) "
                    "VALUES(?,?,?,?,?)", batch)
                conn.executemany(
                    "INSERT INTO asset_files_fts(source_path,asset_id,relative_path) "
                    "VALUES(?,?,?)", [(x[0], x[1], x[2]) for x in batch])
                count += len(batch)
            imported += count
            conn.execute(
                "INSERT OR REPLACE INTO asset_file_sources VALUES(?,?,?,?,?)",
                (str(source), st.st_mtime_ns, st.st_size, time.time(), count),
            )
        old_paths = [r[0] for r in conn.execute("SELECT source_path FROM asset_file_sources")]
        for source in old_paths:
            if source not in current_paths:
                conn.execute("DELETE FROM asset_files WHERE source_path=?", (source,))
                conn.execute("DELETE FROM asset_files_fts WHERE source_path=?", (source,))
                conn.execute("DELETE FROM asset_file_sources WHERE source_path=?", (source,))
                changed += 1
        base_rows = int(conn.execute("SELECT count(*) FROM asset_files").fetchone()[0])
        fts_rows = int(conn.execute("SELECT count(*) FROM asset_files_fts").fetchone()[0])
        if base_rows != fts_rows:
            raise PagerRefused(
                f"REFUSE_ASSET_FTS_CARDINALITY base={base_rows} fts={fts_rows}"
            )
        return {"changed_sources": changed, "imported_files": imported,
                "fts_files": fts_rows, **fts_state}

    @staticmethod
    def key(host: str, path: str) -> str:
        return f"{host}|{path.rstrip('/') or '/'}"

    def _event(self, conn: sqlite3.Connection, key: str | None,
               event: str, reason: str = "", metadata: dict[str, Any] | None = None) -> None:
        conn.execute(
            "INSERT INTO events(at,workspace_key,event,reason,metadata_json) VALUES(?,?,?,?,?)",
            (time.time(), key, event, reason,
             json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)),
        )

    @staticmethod
    def _semantic_values(old: sqlite3.Row | None,
                         asset: dict[str, Any] | None) -> tuple[Any, ...]:
        asset = asset or {}
        asset_revision = int(asset.get("semantic_revision") or 0)
        old_revision = int(old["semantic_revision"] or 0) if old is not None else -1
        asset_annotated = float(asset.get("annotated_at") or 0)
        old_annotated = float(old["annotated_at"] or 0) if old is not None else -1
        use_asset = bool(asset) and (
            asset_revision > old_revision
            or (asset_revision == old_revision and asset_annotated > old_annotated)
        )
        if old is not None and not use_asset:
            return (
                old["content_fingerprint"], old["semantic_revision"],
                old["annotation_status"], old["semantic_summary"],
                old["semantic_keywords_json"], old["annotated_by"],
                old["annotated_at"], old["index_synced_at"],
                old["semantic_stale_task"], old["semantic_stale_at"],
                old["semantic_pending_files_json"],
            )
        status = str(asset.get("annotation_status") or "CURRENT")
        if status not in VALID_ANNOTATION_STATES:
            status = "CURRENT"
        return (
            asset.get("content_fingerprint"), int(asset.get("semantic_revision") or 0),
            status, asset.get("semantic_summary"),
            asset.get("semantic_keywords_json") or "[]", asset.get("annotated_by"),
            asset.get("annotated_at"), asset.get("index_synced_at"),
            None, None, "[]",
        )

    @staticmethod
    def _classification_values(old: sqlite3.Row | None,
                               asset: dict[str, Any] | None,
                               now: float) -> tuple[str, int, str | None, float | None]:
        """Import only an explicit/proven class; never downgrade a manual class."""
        if old is not None and old["redundancy_class"] != "UNCLASSIFIED":
            return (
                old["redundancy_class"], int(old["independent_copies"]),
                old["classification_reason"], old["classified_at"],
            )
        if asset is not None:
            redundancy_class = str(
                asset.get("redundancy_class") or "UNCLASSIFIED"
            ).upper()
            independent_copies = int(asset.get("independent_copies") or 0)
            if redundancy_class not in VALID_REDUNDANCY_CLASSES:
                raise PagerRefused(
                    f"REFUSE_BAD_ASSET_REDUNDANCY_CLASS {redundancy_class}"
                )
            if independent_copies < 0:
                raise PagerRefused(
                    f"REFUSE_BAD_ASSET_INDEPENDENT_COPIES {independent_copies}"
                )
            if redundancy_class != "UNCLASSIFIED":
                reason = str(asset.get("classification_reason") or "").strip()
                if not reason:
                    raise PagerRefused("REFUSE_ASSET_CLASSIFICATION_REASON_REQUIRED")
                classified_at = asset.get("classified_at_epoch") or now
                return redundancy_class, independent_copies, reason, float(classified_at)
        if old is not None:
            return (
                old["redundancy_class"], int(old["independent_copies"]),
                old["classification_reason"], old["classified_at"],
            )
        return "UNCLASSIFIED", 0, None, None

    def sync(self, records: dict[str, dict[str, Any]],
             assets: list[dict[str, Any]], current_host: str) -> dict[str, int]:
        exact_assets = {
            self.key(a["host"], a["original_path"]): a
            for a in assets if a.get("original_path") and a.get("host") in {"mac", "hostb"}
        }
        now = time.time()
        added = updated = mapped = 0
        record_keys = set()
        with self.connect() as conn:
            for rec_key, rec in records.items():
                host, path = rec.get("host") or current_host, rec.get("path") or ""
                if not path:
                    continue
                if is_pager_scratch(path):
                    # Never let the pager manage its own restore staging.
                    continue
                key = self.key(host, path)
                record_keys.add(key)
                old = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
                storage_pool = storage_pool_for(host, path, self.policy)
                handoff_mtime = float(rec.get("mtime") or 0) or None
                asset = exact_assets.get(key)
                if host == current_host:
                    present = int(os.path.exists(path))
                elif asset and asset.get("local_state") in {"replicated", "local"}:
                    present = 1
                elif asset and asset.get("local_state") == "cloud_only":
                    present = 0
                elif old:
                    present = old["local_present"]
                else:
                    present = -1
                cloud_verified = int(bool(asset and asset.get("cloud_verified")))
                restore_verified = int(bool(asset and asset.get("restore_verified")))
                snapshot_verified = int(bool(asset and asset.get("snapshot_verified")))
                archive_epoch = asset.get("indexed_at_epoch") if asset else None
                asset_id = asset.get("asset_id") if asset else None
                size_bytes = asset.get("size_bytes") if asset else None
                last_write = max(handoff_mtime or 0,
                                 (old["last_write"] or 0) if old else 0) or None
                dirty = 1
                if asset and archive_epoch and handoff_mtime and handoff_mtime <= archive_epoch:
                    # This only proves HANDOFF did not change.  A true snapshot
                    # proof is separately required before eviction.
                    dirty = 0
                if old:
                    state = old["state"]
                    pinned = old["pinned"]
                    last_access = old["last_access"]
                    access_count = old["access_count"]
                    lease_until = old["lease_until"]
                    reason = old["reason"]
                    # This is INSERT OR REPLACE: any column left out of the statement
                    # silently reverts to its default, so the liveness probe cache
                    # must be carried forward explicitly or every sync() wipes it and
                    # re-blocks the whole pool on LIVENESS_PROBE_REQUIRED.
                    tree_recent = old["tree_recent"]
                    tree_probed_at = old["tree_probed_at"]
                    tree_probe_days = old["tree_probe_days"]
                    if not asset:
                        asset_id = old["cloud_asset_id"]
                        cloud_verified = old["cloud_verified"]
                        restore_verified = old["restore_verified"]
                        snapshot_verified = old["snapshot_verified"]
                        archive_epoch = old["archive_epoch"]
                        size_bytes = old["size_bytes"]
                        dirty = old["dirty"]
                    elif old["dirty"] and not (
                            cloud_verified and snapshot_verified and archive_epoch
                            and (last_write is None or archive_epoch >= last_write)):
                        # HANDOFF mtime is not the time of the last content write.
                        # A source-match refusal/write hook must survive catalog
                        # reconciliation until a newer confirmed snapshot exists.
                        dirty = 1
                    updated += 1
                else:
                    state, pinned = "WARM", 0
                    last_access = handoff_mtime or now
                    access_count, lease_until, reason = 0, None, "index_sync"
                    tree_recent = tree_probed_at = tree_probe_days = None
                    added += 1
                (redundancy_class, independent_copies,
                 classification_reason, classified_at) = self._classification_values(
                    old, asset, now
                )
                semantics = self._semantic_values(old, asset)
                if storage_pool == "ISOLATED":
                    state = "ISOLATED"
                elif state == "ISOLATED":
                    state = "HOT"
                if auto_pin_applies(path, present):
                    pinned = 1
                if pinned and storage_pool != "ISOLATED":
                    state = "PINNED"
                conn.execute(
                    """INSERT OR REPLACE INTO pages(
                    workspace_key,host,path,state,storage_pool,pinned,local_present,dirty,
                    cloud_asset_id,cloud_verified,restore_verified,snapshot_verified,
                    redundancy_class,independent_copies,classification_reason,classified_at,
                    size_bytes,last_access,last_write,archive_epoch,lease_until,
                    access_count,reason,content_fingerprint,semantic_revision,
                    annotation_status,semantic_summary,semantic_keywords_json,annotated_by,
                    annotated_at,index_synced_at,semantic_stale_task,semantic_stale_at,
                    semantic_pending_files_json,
                    tree_recent,tree_probed_at,tree_probe_days,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                           ?,?,?,?)""",
                    (key, host, path, state, storage_pool, pinned, present, dirty, asset_id,
                     cloud_verified, restore_verified, snapshot_verified,
                     redundancy_class, independent_copies, classification_reason, classified_at,
                     size_bytes,
                     last_access, last_write, archive_epoch, lease_until,
                     access_count, reason, *semantics,
                     tree_recent, tree_probed_at, tree_probe_days, now),
                )
                if asset:
                    mapped += 1

            # A cloud asset is a first-class page even when its original path
            # is a single file or a directory without HANDOFF.md.  Otherwise a
            # successful page-in cannot retain its lease/materialization state.
            for key, asset in exact_assets.items():
                if key in record_keys:
                    continue
                host, path = asset["host"], asset["original_path"]
                storage_pool = storage_pool_for(host, path, self.policy)
                old = conn.execute(
                    "SELECT * FROM pages WHERE workspace_key=?", (key,)
                ).fetchone()
                if host == current_host:
                    present = int(os.path.exists(path))
                elif asset.get("local_state") in {"replicated", "local"}:
                    present = 1
                elif asset.get("local_state") == "cloud_only":
                    present = 0
                else:
                    present = old["local_present"] if old else -1
                cloud_verified = int(bool(asset.get("cloud_verified")))
                restore_verified = int(bool(asset.get("restore_verified")))
                snapshot_verified = int(bool(asset.get("snapshot_verified")))
                archive_epoch = asset.get("indexed_at_epoch")
                if old:
                    state = old["state"]
                    pinned = old["pinned"]
                    dirty = old["dirty"]
                    last_access = old["last_access"]
                    last_write = old["last_write"]
                    lease_until = old["lease_until"]
                    access_count = old["access_count"]
                    reason = old["reason"]
                    # A newly confirmed snapshot supersedes a prior local-write
                    # dirty marker.  Older catalog metadata must never clear it.
                    if (cloud_verified and snapshot_verified and archive_epoch
                            and (last_write is None or archive_epoch >= last_write)):
                        dirty = 0
                    # INSERT OR REPLACE drops any omitted column back to its default,
                    # so the liveness probe cache has to be carried forward here too.
                    tree_recent = old["tree_recent"]
                    tree_probed_at = old["tree_probed_at"]
                    tree_probe_days = old["tree_probe_days"]
                    updated += 1
                else:
                    cloud_only = asset.get("local_state") == "cloud_only"
                    state = "COLD" if present == 0 or (present < 0 and cloud_only) else "WARM"
                    pinned = 0
                    dirty = 0 if snapshot_verified else 1
                    last_access = archive_epoch or now
                    last_write = None
                    lease_until = None
                    access_count = 0
                    reason = "asset_index_sync"
                    tree_recent = tree_probed_at = tree_probe_days = None
                    added += 1
                (redundancy_class, independent_copies,
                 classification_reason, classified_at) = self._classification_values(
                    old, asset, now
                )
                semantics = self._semantic_values(old, asset)
                if storage_pool == "ISOLATED":
                    state = "ISOLATED"
                elif state == "ISOLATED":
                    state = "HOT"
                if auto_pin_applies(path, present):
                    pinned = 1
                if pinned and storage_pool != "ISOLATED":
                    state = "PINNED"
                conn.execute(
                    """INSERT OR REPLACE INTO pages(
                    workspace_key,host,path,state,storage_pool,pinned,local_present,dirty,
                    cloud_asset_id,cloud_verified,restore_verified,snapshot_verified,
                    redundancy_class,independent_copies,classification_reason,classified_at,
                    size_bytes,last_access,last_write,archive_epoch,lease_until,
                    access_count,reason,content_fingerprint,semantic_revision,
                    annotation_status,semantic_summary,semantic_keywords_json,annotated_by,
                    annotated_at,index_synced_at,semantic_stale_task,semantic_stale_at,
                    semantic_pending_files_json,
                    tree_recent,tree_probed_at,tree_probe_days,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                           ?,?,?,?)""",
                    (key, host, path, state, storage_pool, pinned, present, dirty,
                     asset.get("asset_id"), cloud_verified, restore_verified,
                     snapshot_verified, redundancy_class, independent_copies,
                     classification_reason, classified_at, asset.get("size_bytes"), last_access,
                     last_write, archive_epoch, lease_until, access_count, reason,
                     *semantics, tree_recent, tree_probed_at, tree_probe_days, now),
                )
                mapped += 1
            self._event(conn, None, "SYNC", "workspace graph reconciliation",
                        {"records": len(records), "assets": len(assets), "mapped": mapped})
            file_sync = self._sync_asset_files(conn)
            file_rows = conn.execute("SELECT count(*) FROM asset_files").fetchone()[0]
        return {"added": added, "updated": updated, "mapped": mapped,
                "asset_files": int(file_rows), **file_sync}

    def touch(self, host: str, path: str, reason: str,
              lease_hours: float = 8.0) -> dict[str, Any]:
        if is_pager_scratch(path):
            raise PagerRefused(f"REFUSE_PAGER_SCRATCH_AS_WORKSPACE {path}")
        # Normalise before the key is built: an un-folded hostname writes a row
        # that storage_pool_for() will class EXTERNAL, permanently outside paging.
        host = _host_name(host)
        if host not in CANONICAL_HOSTS:
            raise PagerRefused(f"REFUSE_UNKNOWN_HOST {host}")
        key, now = self.key(host, path), time.time()
        storage_pool = storage_pool_for(host, path, self.policy)
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if not row:
                conn.execute(
                    """INSERT INTO pages(workspace_key,host,path,state,local_present,
                    storage_pool,last_access,lease_until,access_count,reason,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (key, host, path,
                     "ISOLATED" if storage_pool == "ISOLATED" else "HOT",
                     int(os.path.exists(path)), storage_pool, now,
                     now + lease_hours * 3600, 1, reason, now),
                )
            else:
                state = ("ISOLATED" if row["storage_pool"] == "ISOLATED" else
                         "PINNED" if row["pinned"] else "HOT")
                conn.execute(
                    """UPDATE pages SET state=?,last_access=?,lease_until=?,
                    access_count=access_count+1,reason=?,updated_at=?,local_present=?
                    WHERE workspace_key=?""",
                    (state, now, max(row["lease_until"] or 0, now + lease_hours * 3600),
                     reason, now, int(os.path.exists(path)) if host == "mac" else row["local_present"], key),
                )
            self._event(conn, key, "TOUCH", reason, {"lease_hours": lease_hours})
            return dict(conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone())

    def release_lease(self, host: str, path: str, reason: str) -> dict[str, Any]:
        """Drop a production lease taken via touch() once the producer is done.

        Incident note: asset-pool-v3 renewed an 8h "active production" lease
        on batch-0001 at every tick (access_count 310) and then simply stopped once the
        Logical Vault upload passed -- leaving last_access at the final renewal, so a
        fully cloud-proven ~80GB tree stayed KEEP_HOT for another hot_days while the
        pool sat at 7% free. A lease is a statement about the producer, not about
        anyone reading the tree; when the producer releases it, logical access falls
        back to the tree's own evidence (last_write, else archive_epoch), never
        forward. No-op if the page is unknown or pinned; state is recomputed as
        WARM (local+cloud) / HOT (local only) / COLD (cloud only).
        """
        host = _host_name(host)
        key, now = self.key(host, path), time.time()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if not row:
                raise PagerRefused(f"REFUSE_PAGE_UNKNOWN {key}")
            if row["pinned"] or row["storage_pool"] == "ISOLATED":
                return dict(row)
            evidence = row["last_write"] or row["archive_epoch"]
            last_access = row["last_access"]
            if evidence and (last_access is None or evidence < last_access):
                last_access = float(evidence)
            state = ("WARM" if row["local_present"] and row["cloud_verified"] else
                     "COLD" if row["cloud_verified"] else "HOT")
            conn.execute(
                """UPDATE pages SET state=?,last_access=?,lease_until=NULL,reason=?,updated_at=?
                WHERE workspace_key=?""",
                (state, last_access, reason, now, key),
            )
            self._event(conn, key, "LEASE_RELEASED", reason,
                        {"previous_last_access": row["last_access"],
                         "previous_lease_until": row["lease_until"],
                         "last_access": last_access, "state": state})
            return dict(conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone())

    def set_pin(self, host: str, path: str, pinned: bool, reason: str) -> dict[str, Any]:
        key, now = self.key(host, path), time.time()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if not row:
                raise PagerRefused(f"REFUSE_PAGE_UNKNOWN {key}")
            if pinned and row["local_present"] != 1:
                raise PagerRefused(f"REFUSE_PIN_REQUIRES_LOCAL_COPY {key}")
            state = ("ISOLATED" if row["storage_pool"] == "ISOLATED" else
                     "PINNED" if pinned else
                     "HOT" if row["local_present"] == 1 else
                     "COLD" if row["local_present"] == 0 else "WARM")
            conn.execute(
                "UPDATE pages SET pinned=?,state=?,reason=?,updated_at=? WHERE workspace_key=?",
                (int(pinned), state, reason, now, key),
            )
            self._event(conn, key, "PIN" if pinned else "UNPIN", reason)
            return dict(conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone())

    def set_classification(self, host: str, path: str, redundancy_class: str,
                           independent_copies: int, reason: str) -> dict[str, Any]:
        key, now = self.key(host, path), time.time()
        redundancy_class = redundancy_class.upper()
        if redundancy_class not in VALID_REDUNDANCY_CLASSES - {"UNCLASSIFIED"}:
            raise PagerRefused(f"REFUSE_BAD_REDUNDANCY_CLASS {redundancy_class}")
        if independent_copies < 0:
            raise PagerRefused(f"REFUSE_BAD_INDEPENDENT_COPIES {independent_copies}")
        if not reason.strip():
            raise PagerRefused("REFUSE_CLASSIFICATION_REASON_REQUIRED")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if not row:
                raise PagerRefused(f"REFUSE_PAGE_UNKNOWN {key}")
            conn.execute(
                """UPDATE pages SET redundancy_class=?,independent_copies=?,
                classification_reason=?,classified_at=?,reason=?,updated_at=?
                WHERE workspace_key=?""",
                (redundancy_class, independent_copies, reason, now,
                 "redundancy classification", now, key),
            )
            self._event(conn, key, "CLASSIFY", reason, {
                "redundancy_class": redundancy_class,
                "independent_copies": independent_copies,
                "copies_exclude_local_source": True,
            })
            return dict(conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone())

    def mark_dirty(self, host: str, path: str, reason: str) -> None:
        key, now = self.key(host, path), time.time()
        storage_pool = storage_pool_for(host, path, self.policy)
        with self.connect() as conn:
            row = conn.execute("SELECT 1 FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if row:
                conn.execute(
                    "UPDATE pages SET dirty=1,last_write=?,reason=?,updated_at=? "
                    "WHERE workspace_key=?",
                    (now, reason, now, key),
                )
            else:
                conn.execute(
                    """INSERT INTO pages(workspace_key,host,path,state,local_present,
                    storage_pool,dirty,last_write,last_access,reason,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (key, host, path,
                     "ISOLATED" if storage_pool == "ISOLATED" else "HOT",
                     int(os.path.exists(path)), storage_pool, 1,
                     now, now, reason, now),
                )
            self._event(conn, key, "DIRTY", reason)

    def mark_semantic_stale(self, host: str, path: str, changed_files: Iterable[str],
                            actor: str, task_id: str | None = None) -> dict[str, Any]:
        key, now = self.key(host, path), time.time()
        storage_pool = storage_pool_for(host, path, self.policy)
        files = sorted({os.path.abspath(str(x)) for x in changed_files if str(x).strip()
                        and os.path.basename(str(x)) != "HANDOFF.md"})
        if not files:
            return {"workspace_key": key, "changed": False}
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            pending = []
            stale_task = task_id or "interactive"
            if row:
                try:
                    pending = list(json.loads(row["semantic_pending_files_json"] or "[]"))
                except (json.JSONDecodeError, TypeError):
                    pending = []
                old_task = row["semantic_stale_task"]
                if (row["annotation_status"] != "CURRENT" and old_task
                        and old_task != stale_task):
                    stale_task = "MULTIPLE"
                state = ("ISOLATED" if row["storage_pool"] == "ISOLATED" else
                         "PINNED" if row["pinned"] else "HOT")
                conn.execute(
                    """UPDATE pages SET state=?,dirty=1,last_write=?,reason=?,
                    annotation_status='SEMANTIC_STALE',semantic_stale_task=?,semantic_stale_at=?,
                    semantic_pending_files_json=?,updated_at=? WHERE workspace_key=?""",
                    (state, now, "semantic content write", stale_task, now,
                     json.dumps(sorted(set(pending + files)), ensure_ascii=False), now, key),
                )
            else:
                state = "ISOLATED" if storage_pool == "ISOLATED" else "HOT"
                conn.execute(
                    """INSERT INTO pages(workspace_key,host,path,state,storage_pool,
                    local_present,dirty,last_write,last_access,reason,annotation_status,
                    semantic_stale_task,semantic_stale_at,semantic_pending_files_json,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (key, host, path, state, storage_pool, int(os.path.exists(path)), 1,
                     now, now, "semantic content write", "SEMANTIC_STALE", stale_task,
                     now, json.dumps(files, ensure_ascii=False), now),
                )
            self._event(conn, key, "SEMANTIC_STALE", actor, {
                "task_id": stale_task, "files": files[:50], "file_count": len(files),
            })
            return dict(conn.execute(
                "SELECT * FROM pages WHERE workspace_key=?", (key,)
            ).fetchone())

    def annotate(self, host: str, path: str, summary: str, keywords: Iterable[str],
                 actor: str, task_id: str | None = None) -> dict[str, Any]:
        key, now = self.key(host, path), time.time()
        summary = summary.strip()
        actor = actor.strip()
        keyword_list = sorted({str(x).strip() for x in keywords if str(x).strip()})
        if not summary or len(summary) > 4000:
            raise PagerRefused("REFUSE_SEMANTIC_SUMMARY_REQUIRED_OR_TOO_LONG")
        if not actor or len(keyword_list) > 50:
            raise PagerRefused("REFUSE_SEMANTIC_ACTOR_OR_KEYWORDS")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
            if not row:
                raise PagerRefused(f"REFUSE_PAGE_UNKNOWN {key}")
            if row["annotation_status"] != "SEMANTIC_STALE":
                raise PagerRefused(
                    f"REFUSE_PAGE_NOT_SEMANTIC_STALE status={row['annotation_status']}"
                )
            stale_task = row["semantic_stale_task"] or "interactive"
            expected_task = task_id or "interactive"
            if stale_task == "MULTIPLE" or stale_task != expected_task:
                raise PagerRefused(
                    f"REFUSE_SEMANTIC_TASK_MISMATCH stale={stale_task} got={expected_task}"
                )
            try:
                pending = sorted(set(json.loads(row["semantic_pending_files_json"] or "[]")))
            except (json.JSONDecodeError, TypeError) as exc:
                raise PagerRefused("REFUSE_SEMANTIC_PENDING_FILES_INVALID") from exc
            root = os.path.normpath(path)
            for changed in pending:
                if not _path_is_at_or_below(changed, root):
                    raise PagerRefused(
                        f"REFUSE_SEMANTIC_FILE_OUTSIDE_WORKSPACE file={changed} workspace={root}"
                    )
            entries = [_content_entry(Path(changed)) for changed in pending]
            previous = row["content_fingerprint"] or ("0" * 64)
            revision = int(row["semantic_revision"] or 0) + 1
            payload = json.dumps({
                "previous": previous, "revision": revision, "changes": entries,
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            keywords_json = json.dumps(keyword_list, ensure_ascii=False, sort_keys=True)
            conn.execute(
                """INSERT OR REPLACE INTO page_semantics(
                workspace_key,summary,keywords_json,semantic_revision,content_fingerprint,
                annotated_by,annotated_at,index_synced_at) VALUES(?,?,?,?,?,?,?,?)""",
                (key, summary, keywords_json, revision, fingerprint, actor, now, now),
            )
            conn.execute("DELETE FROM page_semantics_fts WHERE workspace_key=?", (key,))
            conn.execute(
                "INSERT INTO page_semantics_fts(workspace_key,summary,keywords) VALUES(?,?,?)",
                (key, summary, " ".join(keyword_list)),
            )
            conn.execute(
                """UPDATE pages SET content_fingerprint=?,semantic_revision=?,
                annotation_status='CURRENT',semantic_summary=?,semantic_keywords_json=?,
                annotated_by=?,annotated_at=?,index_synced_at=?,semantic_stale_task=NULL,
                semantic_stale_at=NULL,semantic_pending_files_json='[]',reason=?,updated_at=?
                WHERE workspace_key=?""",
                (fingerprint, revision, summary, keywords_json, actor, now, now,
                 "semantic annotation synced", now, key),
            )
            self._event(conn, key, "SEMANTIC_ANNOTATED", actor, {
                "task_id": expected_task, "revision": revision,
                "content_fingerprint": fingerprint, "changed_files": len(entries),
            })
            return dict(conn.execute(
                "SELECT * FROM pages WHERE workspace_key=?", (key,)
            ).fetchone())

    def mark_annotation_sync_failed(self, host: str, path: str, reason: str) -> None:
        key, now = self.key(host, path), time.time()
        with self.connect() as conn:
            conn.execute(
                "UPDATE pages SET annotation_status='SYNC_FAILED',reason=?,updated_at=? "
                "WHERE workspace_key=?", (reason, now, key),
            )
            self._event(conn, key, "SEMANTIC_SYNC_FAILED", reason)

    def mark_annotation_sync_complete(self, host: str, path: str,
                                      reason: str = "semantic cloud sync retry PASS") -> dict[str, Any]:
        """Close only an already-written SYNC_FAILED annotation, without revision churn."""
        key, now = self.key(host, path), time.time()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM pages WHERE workspace_key=?", (key,)
            ).fetchone()
            if not row:
                raise PagerRefused(f"REFUSE_PAGE_UNKNOWN {key}")
            if row["annotation_status"] != "SYNC_FAILED":
                raise PagerRefused(
                    f"REFUSE_PAGE_NOT_SYNC_FAILED status={row['annotation_status']}"
                )
            semantic = conn.execute(
                "SELECT 1 FROM page_semantics WHERE workspace_key=?", (key,)
            ).fetchone()
            if not semantic:
                raise PagerRefused(f"REFUSE_SEMANTIC_ROW_MISSING {key}")
            conn.execute(
                "UPDATE page_semantics SET index_synced_at=? WHERE workspace_key=?",
                (now, key),
            )
            conn.execute(
                "UPDATE pages SET annotation_status='CURRENT',index_synced_at=?,reason=?,updated_at=? "
                "WHERE workspace_key=?",
                (now, reason, now, key),
            )
            self._event(conn, key, "SEMANTIC_SYNC_RECOVERED", reason, {
                "semantic_revision": int(row["semantic_revision"] or 0),
                "content_fingerprint": row["content_fingerprint"],
            })
            return dict(conn.execute(
                "SELECT * FROM pages WHERE workspace_key=?", (key,)
            ).fetchone())

    def semantic_gate(self, task_id: str, paths: Iterable[str] | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT workspace_key,host,path,annotation_status,semantic_stale_task,"
                "semantic_stale_at FROM pages WHERE annotation_status!='CURRENT' "
                "AND (semantic_stale_task=? OR semantic_stale_task='MULTIPLE') ORDER BY path",
                (task_id,),
            ).fetchall()
        allowed = {os.path.normpath(x) for x in (paths or [])}
        return [dict(row) for row in rows
                if not allowed or os.path.normpath(row["path"]) in allowed]

    def export_semantics(self, path: Path) -> int:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT p.host,p.path,p.cloud_asset_id,s.* FROM page_semantics s "
                "JOIN pages p USING(workspace_key) ORDER BY p.host,p.path"
            ).fetchall()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
        with tmp.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)
        return len(rows)

    def mark_restore_verified(self, asset_id: str, evidence: str) -> int:
        now = time.time()
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE pages SET restore_verified=1,updated_at=? WHERE cloud_asset_id=?",
                (now, asset_id),
            )
            self._event(conn, None, "RESTORE_PASS", evidence, {"asset_id": asset_id})
            return cur.rowcount

    def mark_materialized(self, asset_id: str, evidence: str) -> int:
        now = time.time()
        with self.connect() as conn:
            cur = conn.execute(
                """UPDATE pages SET local_present=1,state=CASE WHEN pinned=1 THEN
                'PINNED' ELSE 'HOT' END,last_access=?,lease_until=?,reason=?,updated_at=?
                WHERE cloud_asset_id=?""",
                (now, now + 8 * 3600, evidence, now, asset_id),
            )
            self._event(conn, None, "MATERIALIZED", evidence, {"asset_id": asset_id})
            return cur.rowcount

    def status(self, target: str | None = None) -> dict[str, Any]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM pages WHERE workspace_key=? OR path=? OR cloud_asset_id=? "
                    "ORDER BY path",
                    (target, target, target),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM pages ORDER BY host,path").fetchall()
        data = [dict(r) for r in rows]
        counts = {s: sum(1 for r in data if r["state"] == s) for s in sorted(VALID_STATES)}
        classes = {
            s: sum(1 for r in data if r["redundancy_class"] == s)
            for s in sorted(VALID_REDUNDANCY_CLASSES)
        }
        disk = shutil.disk_usage(HOME)
        return {
            "database": str(self.db_path), "rows": data, "count": len(data),
            "states": counts,
            "redundancy_classes": classes,
            "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
        }

    _LIVENESS_PROBE_SH = (
        'while IFS= read -r p; do\n'
        '  if [ -L "$p" ] || [ ! -e "$p" ]; then printf "M\\t%s\\n" "$p"; continue; fi\n'
        '  if h=$(find "$p" -type f -newermt "-__W__ days" -print -quit 2>/dev/null); then\n'
        '    if [ -n "$h" ]; then printf "1\\t%s\\n" "$p"; else printf "0\\t%s\\n" "$p"; fi\n'
        '  else printf "M\\t%s\\n" "$p"; fi\n'
        'done\n'
    )

    def _probe_tree_recent(self, host: str, paths: list[str],
                           window_days: float) -> dict[str, int | None]:
        """Does each tree contain a file modified within ``window_days``?

        Uses ``find -newermt ... -print -quit`` so it short-circuits on the first
        hit: a live 70GB tree answers in ~0ms, a genuinely cold 80GB tree in ~40ms.
        Returns 1 (live), 0 (cold) or None (missing/unprobeable -> caller must
        fail closed rather than assume cold).
        """
        if not paths:
            return {}
        unknown = {path: None for path in paths}
        if host not in {"mac", "hostb"} or any(
            not path.startswith("/") or any(char in path for char in "\n\r\t\0")
            for path in paths
        ):
            return unknown
        script = self._LIVENESS_PROBE_SH.replace("__W__", str(int(max(1, window_days))))
        payload = "\n".join(paths) + "\n"
        if host != _self_host():
            address = {"hostb": "user@host-b", "mac": "user@host-a"}[host]
            cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
                   address, "bash -c " + shlex.quote(script)]
        else:
            cmd = ["bash", "-c", script]
        try:
            proc = subprocess.run(cmd, input=payload, text=True,
                                  capture_output=True, timeout=900)
        except (subprocess.TimeoutExpired, OSError):
            return unknown
        if proc.returncode:
            return unknown
        out: dict[str, int | None] = {p: None for p in paths}
        for line in proc.stdout.splitlines():
            flag, _, path = line.partition("\t")
            if path in out:
                out[path] = {"1": 1, "0": 0}.get(flag)
        return out

    def refresh_tree_liveness(self, rows: list[sqlite3.Row] | None = None,
                              window_days: float | None = None,
                              ttl_sec: float = 6 * 3600) -> dict[str, int]:
        """Refresh the cached filesystem-recency probe for MANAGED pages.

        Only re-probes rows whose cached answer is missing, older than ``ttl_sec``,
        or was taken with a different window, so repeated calls are cheap.

        <date>: the window is its own policy key.  It used to piggyback on
        ``cold_days``, so filesystem evidence silently got a 15-day hot window while
        HANDOFF evidence got 3 -- the same tree was "hot" or "warm" depending on which
        clock you asked.  ``liveness_window_days`` now defaults to ``hot_days`` so both
        answer to one hot/warm boundary.  This agent-b only decides *archivability*
        (upload, source retained); deletion is gated separately by the water level plus
        the cloud/restore/snapshot/redundancy chain.
        """
        if window_days is not None:
            window = float(window_days)
        else:
            window = float(self.policy.get("liveness_window_days")
                           or self.policy.get("hot_days", 3))
        now = time.time()
        with self.connect() as conn:
            if rows is None:
                # Not just MANAGED: plan() runs EXTERNAL pages through the same
                # cooling chain, so they need the same filesystem evidence.
                # ISOLATED is short-circuited before any cooling decision.
                # local_present=-1 means "not yet determined" and covers the bulk of
                # the pool (1606/2025 rows on hostb), including nearly every archive
                # candidate; only a confirmed-absent page (0) has nothing to probe.
                rows = conn.execute(
                    "SELECT * FROM pages WHERE storage_pool!='ISOLATED' AND local_present!=0"
                ).fetchall()
            stale = [r for r in rows
                     if r["tree_recent"] is None
                     or not r["tree_probed_at"]
                     or (now - float(r["tree_probed_at"])) > ttl_sec
                     or float(r["tree_probe_days"] or -1) != window]
            by_host: dict[str, list[str]] = {}
            for row in stale:
                by_host.setdefault(row["host"], []).append(row["path"])
            probed = 0
            live = 0
            for host, paths in by_host.items():
                answers = self._probe_tree_recent(host, paths, window)
                updates = []
                for path, flag in answers.items():
                    if flag is None:
                        updates.append((None, now, window, host, path))
                        continue
                    probed += 1
                    live += flag
                    updates.append((flag, now, window, host, path))
                if updates:
                    conn.executemany(
                        """UPDATE pages SET tree_recent=?,tree_probed_at=?,tree_probe_days=?
                        WHERE host=? AND path=?""", updates)
            if probed:
                self._event(conn, None, "TREE_LIVENESS_PROBE", "filesystem recency",
                            {"probed": probed, "live": live, "window_days": window})
        return {"considered": len(rows), "stale": len(stale),
                "probed": probed, "live": live, "window_days": window}

    def plan(self, hot_days: float | None = None,
             cold_days: float | None = None) -> list[dict[str, Any]]:
        """Classify every page.  Defaults come from policy, never from a literal.

        <date> contract fix: the 15-day cooling schedule is retired.  It was a
        leftover of the age-driven scheme; the shipped institution is water-level
        driven (10% trigger / 15% stop) with WARM defined as "local *and* cloud
        co-held".  Under the old schedule a page aged hot_days..15 sat in
        COOL_TO_WARM: labelled WARM, therefore counted as warm capacity, yet never
        uploaded -- so it could never become evictable and the pool could never
        drain.  206 pages / 82.9GB were stuck there.  WARM now means the archive
        pipeline owns the page; ``hot_days`` plus the tree-liveness probe is the
        only hot/warm boundary.
        """
        if hot_days is None:
            hot_days = float(self.policy.get("hot_days", 3))
        if cold_days is None:
            cold_days = float(self.policy.get("cold_days", hot_days))
        now = time.time()
        rows = self.status()["rows"]
        out = []
        transitions = []
        for row in rows:
            probe_window = float(self.policy.get("liveness_window_days") or hot_days)
            probe_age = now - float(row["tree_probed_at"] or 0)
            if (not 0 <= probe_age <= 6 * 3600
                    or float(row["tree_probe_days"] or -1) != probe_window):
                row["tree_recent"] = None
            age_days = (now - (row["last_access"] or row["updated_at"])) / 86400
            leased = bool(row["lease_until"] and row["lease_until"] > now)
            if row["storage_pool"] == "ISOLATED":
                action = "KEEP_ISOLATED"
                desired_state = "ISOLATED"
            elif row["local_present"] == 0 and row["cloud_verified"]:
                action = "KEEP_COLD"
                desired_state = "COLD"
            elif row["local_present"] == 0:
                # Gone locally and never reached the cloud: an orphan index record, not
                # a page.  Without this branch it fell through to the archive chain,
                # which demands a filesystem-liveness probe -- but refresh_tree_liveness
                # skips local_present=0 rows (nothing to stat), so 188 deleted agent-b
                # research dirs sat permanently LIVENESS_PROBE_REQUIRED, a probe that
                # could never be satisfied.  No pipeline consumes this action, and the
                # state is left untouched so it produces no transition churn.
                action = "RECORD_ORPHANED"
                desired_state = row["state"]
            elif row["pinned"] or leased:
                action = "KEEP_HOT"
                desired_state = "PINNED" if row["pinned"] else "HOT"
            elif row["tree_recent"] == 1:
                # Live tree.  ``last_access`` is frozen at HANDOFF.md's mtime, so a
                # busy workspace whose HANDOFF is stale otherwise reads as ancient
                # and gets archived/evicted while it is still being written.
                action = "KEEP_HOT"
                desired_state = "HOT"
            elif age_days < hot_days:
                action = "KEEP_HOT"
                desired_state = "HOT"
            elif age_days < cold_days:
                action = "COOL_TO_WARM"
                desired_state = "WARM"
            elif row["annotation_status"] != "CURRENT":
                action = "SEMANTIC_PATCH_REQUIRED"
                desired_state = "WARM"
            elif not row["cloud_verified"]:
                # Fail closed: never spend an upload on a tree we have no filesystem
                # evidence is cold.  HANDOFF mtime alone already misclassified live
                # 70GB workspaces as ancient.
                action = ("ARCHIVE_CANDIDATE" if row["tree_recent"] == 0
                          else "LIVENESS_PROBE_REQUIRED")
                desired_state = "WARM"
            elif not row["snapshot_verified"] or row["dirty"]:
                action = "REARCHIVE_REQUIRED"
                desired_state = "WARM"
            elif row["redundancy_class"] == "UNCLASSIFIED":
                action = "CLASSIFY_REQUIRED"
                desired_state = "WARM"
            elif row["independent_copies"] < MIN_INDEPENDENT_COPIES[row["redundancy_class"]]:
                action = "RETAIN_REDUNDANCY_REQUIRED"
                desired_state = "WARM"
            elif row["local_present"] == 1:
                # Deleting the local copy is the one irreversible step; require
                # positive filesystem evidence the tree is cold before allowing it.
                action = ("EVICT_CANDIDATE" if row["tree_recent"] == 0
                          else "LIVENESS_PROBE_REQUIRED")
                desired_state = "WARM"
            else:
                action = "KEEP_COLD"
                desired_state = "COLD"
            if desired_state != row["state"]:
                transitions.append((desired_state, now, row["workspace_key"]))
            out.append({
                "workspace_key": row["workspace_key"], "host": row["host"],
                "path": row["path"], "state": desired_state,
                "storage_pool": row["storage_pool"],
                "age_days": round(age_days, 3), "action": action,
                "asset_id": row["cloud_asset_id"], "size_bytes": row["size_bytes"],
                "last_access": row["last_access"], "access_count": row["access_count"],
                "annotation_status": row["annotation_status"],
                "content_fingerprint": row["content_fingerprint"],
                "redundancy_class": row["redundancy_class"],
                "independent_copies": row["independent_copies"],
                "required_independent_copies": MIN_INDEPENDENT_COPIES[row["redundancy_class"]],
                "tree_recent": row["tree_recent"],
                "tree_probed_at": row["tree_probed_at"],
            })
        if transitions and not self.read_only:
            with self.connect() as conn:
                conn.executemany(
                    "UPDATE pages SET state=?,updated_at=? WHERE workspace_key=?", transitions)
                self._event(conn, None, "TEMPERATURE_RECONCILE", "policy plan",
                            {"transitions": len(transitions), "hot_days": hot_days,
                             "cold_days": cold_days})
        out.sort(key=lambda x: (-x["age_days"], x["workspace_key"]))
        return out

    def _meta_get(self, conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
        row = conn.execute("SELECT value_json FROM pager_meta WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return default

    def _meta_set(self, conn: sqlite3.Connection, key: str, value: Any) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO pager_meta(key,value_json,updated_at) VALUES(?,?,?)",
            (key, json.dumps(value, ensure_ascii=False, sort_keys=True), time.time()),
        )

    def request_capacity(self, owner: str, target_free_bytes: int, *,
                         batch_id: str, manifest_sha256: str, ttl: int = 3600) -> dict:
        """Short-lived demand on the managed pool; never authorizes a deletion.

        Only the existing sequential tool intake is admitted for now. A stopped
        producer cannot leave a permanent pressure flag. Multiple registrations
        are transactional; renewals replace this owner's demand, not add to it.
        """
        if (owner != 'asset-pool-v3' or type(target_free_bytes) is not int
                or target_free_bytes < 0 or not re.fullmatch(r'batch-[0-9]{4}', batch_id)
                or not re.fullmatch(r'[0-9a-f]{64}', manifest_sha256)
                or type(ttl) is not int or not 60 <= ttl <= 7200):
            raise PagerRefused('REFUSE_INVALID_CAPACITY_REQUEST')
        request = dict(owner=owner, target_free_bytes=target_free_bytes,
                       batch_id=batch_id, manifest_sha256=manifest_sha256,
                       expires_at=time.time() + ttl)
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            requests = self._meta_get(conn, 'capacity_requests', {})
            if not isinstance(requests, dict):
                raise PagerRefused('REFUSE_INVALID_CAPACITY_LEDGER')
            requests[owner] = request
            self._meta_set(conn, 'capacity_requests', requests)
        return request

    def release_capacity(self, owner: str, *, batch_id: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            requests = self._meta_get(conn, 'capacity_requests', {})
            if not isinstance(requests, dict):
                raise PagerRefused('REFUSE_INVALID_CAPACITY_LEDGER')
            prior = requests.get(owner)
            if prior and (batch_id is None or prior.get('batch_id') == batch_id):
                del requests[owner]
                self._meta_set(conn, 'capacity_requests', requests)

    @staticmethod
    def _remote_disk_usage(mount: str) -> dict[str, Any]:
        proc = subprocess.run(
            ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
             "user@host-b",
             "df -B1 --output=size,used,avail,target -- %s | tail -1"
             % subprocess.list2cmdline([mount])],
            text=True, capture_output=True, timeout=15,
        )
        if proc.returncode:
            raise PagerRefused(
                f"REFUSE_PAGER_DF_hostb rc={proc.returncode} detail={proc.stderr[-500:]}"
            )
        cols = proc.stdout.split()
        if len(cols) != 4:
            raise PagerRefused(f"REFUSE_PAGER_DF_PARSE output={proc.stdout!r}")
        total, used, free = map(int, cols[:3])
        return {"mount": cols[3], "total": total, "used": used, "free": free,
                "free_ratio": free / total if total else 0.0}

    def pool_status(self, disk_stats: dict[str, dict[str, Any]] | None = None,
                    update_hysteresis: bool = True) -> dict[str, Any]:
        cfg = self.policy
        if disk_stats is None:
            disk_stats = {
                "managed": self._remote_disk_usage(cfg["managed_mount"]),
                "isolated": self._remote_disk_usage(cfg["isolation_mount"]),
            }
        managed = dict(disk_stats["managed"])
        isolated = dict(disk_stats["isolated"])
        managed["free_ratio"] = managed.get("free_ratio", managed["free"] / managed["total"])
        isolated["free_ratio"] = isolated.get("free_ratio", isolated["free"] / isolated["total"])
        with self.connect() as conn:
            active = bool(self._meta_get(conn, "managed_eviction_active", False))
            if managed["free_ratio"] < float(cfg["low_free_ratio"]):
                active = True
            elif active and managed["free_ratio"] >= float(cfg["stop_free_ratio"]):
                active = False
            if update_hysteresis and not self.read_only:
                self._meta_set(conn, "managed_eviction_active", active)
            requests = self._meta_get(conn, 'capacity_requests', {})
            if not isinstance(requests, dict):
                raise PagerRefused('REFUSE_INVALID_CAPACITY_LEDGER')
            demands = [r for r in requests.values()
                       if isinstance(r, dict) and r.get('owner') == 'asset-pool-v3'
                       and isinstance(r.get('expires_at'), (int, float))
                       and time.time() < r['expires_at'] <= time.time() + 7201
                       and type(r.get('target_free_bytes')) is int
                       and 0 <= r['target_free_bytes'] <= managed['total']]
            rows = conn.execute(
                "SELECT state,storage_pool,local_present,coalesce(size_bytes,0) size_bytes "
                "FROM pages WHERE host='hostb'"
            ).fetchall()
        known_hot = sum(int(r["size_bytes"]) for r in rows
                        if r["storage_pool"] == "MANAGED" and r["local_present"] == 1
                        and r["state"] in {"HOT", "PINNED"})
        known_warm = sum(int(r["size_bytes"]) for r in rows
                         if r["storage_pool"] == "MANAGED" and r["local_present"] == 1
                         and r["state"] == "WARM")
        usable = int(managed["total"] * (1.0 - float(cfg["low_free_ratio"])))
        demand_target = max([r['target_free_bytes'] for r in demands], default=0)
        capacity_pending = demand_target > managed['free']
        target = max(int(managed['total'] * float(cfg['stop_free_ratio'])) if active else 0,
                     demand_target)
        managed.update({
            "trigger_free_ratio": float(cfg["low_free_ratio"]),
            "stop_free_ratio": float(cfg["stop_free_ratio"]),
            "eviction_active": active or capacity_pending,
            "watermark_eviction_active": active,
            "capacity_pending": capacity_pending,
            "capacity_requests": demands,
            "target_free_bytes": target,
            "capacity_gap_bytes": max(0, demand_target - managed['free']),
            "bytes_to_stop": max(0, target - int(managed["free"])),
            "usable_bytes": usable,
            "hot_target_bytes": int(usable * float(cfg["hot_ratio"])),
            "warm_target_bytes": int(usable * float(cfg["warm_ratio"])),
            "known_hot_bytes": known_hot,
            "known_warm_bytes": known_warm,
        })
        isolated["warn_free_ratio"] = float(cfg["isolation_warn_free_ratio"])
        isolated["err_free_ratio"] = float(
            cfg.get("isolation_err_free_ratio", DEFAULT_ISOLATION_ERR_FREE_RATIO))
        return {"managed": managed, "isolated": isolated,
                "migration_state": cfg.get("pool_migration_state", "UNKNOWN")}

    EVICT_BLOCK_META = "evict_blocked"

    def eviction_blocks(self, max_age_days: float | None = None) -> dict[str, dict[str, Any]]:
        """Assets whose executor deterministically refused deletion (REFUSE_*/NO_ELIGIBLE).

        <date>: the v2 evict tool fail-closes on sources outside its ALLOWED_PREFIXES
        (e.g. /home/user/.agent-agent-f/research/hardening-skills, 114KB). The pager
        cannot see that allowlist, so without this ledger it kept presenting the page as
        EVICT_CANDIDATE, the pressure loop kept aborting on it every 10 minutes, and a
        ~80GB batch behind it was never reached. A block is a persisted page fact, not a
        silence: PAGER_PRESSURE_STUCK reports it, and ``ws page evict-unblock`` clears it.

        Incident note: this ledger was **permanent** while its archive-side twin
        (:meth:`archive_blocks`) has always expired entries.  One transient refusal --
        ``REFUSE_SOURCE_HAS_OPEN_HANDLES`` (somebody held the file open for a second),
        ``REFUSE_PRESSURE_WITHOUT_ELIGIBLE_WARM_PAGE`` (a momentarily empty pool) --
        blacklisted an asset forever, so the candidate pool could only shrink and the
        evictor starved by construction.  Measured on <date>: 383 entries, hand-cleared;
        by <date> it had regrown to 192 with **zero** of them carrying any expiry, free
        space fell back to 6.10% and PAGER_PRESSURE_STUCK went err again.  Hand-clearing
        treats the symptom; the missing expiry is the mechanism bug.

        This is **not** a relaxation of fail-closed: an expired entry merely returns to
        the pool to be *re-judged*.  Every refusal predicate runs again from scratch and
        a still-invalid asset is re-blocked on the spot -- now with ``count`` accumulating,
        so "refused once by accident" stops looking identical to "refused 200 times
        because it genuinely cannot be deleted".  Callers that want the raw ledger for
        display (``ws page eviction-blocks``, the PAGER_PRESSURE_STUCK detail line) keep
        calling with no argument and still see every entry, expired or not.
        """
        with self.connect() as conn:
            raw = self._meta_get(conn, self.EVICT_BLOCK_META, {}) or {}
        if not isinstance(raw, dict):
            return {}
        if max_age_days is None:
            return raw
        cutoff = time.time() - float(max_age_days) * 86400
        now = time.time()
        return {key: value for key, value in raw.items()
                if float((value or {}).get("at") or 0) >= cutoff
                and ("retry_at" not in (value or {})
                     or float(value["retry_at"]) > now)}

    def block_eviction(self, asset_id: str, reason: str,
                       retry_after_sec: float | None = None) -> dict[str, Any]:
        """Record an executor refusal.  Mirrors :meth:`block_archive` field for field."""
        if retry_after_sec is not None and retry_after_sec <= 0:
            raise PagerRefused("REFUSE_EVICT_RETRY_INTERVAL")
        now = time.time()
        with self.connect() as conn:
            raw = self._meta_get(conn, self.EVICT_BLOCK_META, {}) or {}
            previous = raw.get(str(asset_id)) or {}
            raw[str(asset_id)] = {
                "reason": str(reason)[:500], "at": now,
                "count": int(previous.get("count") or 0) + 1,
            }
            if retry_after_sec is not None:
                raw[str(asset_id)]["retry_at"] = now + retry_after_sec
            self._meta_set(conn, self.EVICT_BLOCK_META, raw)
            self._event(conn, None, "EVICT_BLOCKED", str(reason)[:500],
                        {"asset_id": asset_id})
        return raw[str(asset_id)]

    def unblock_eviction(self, asset_id: str, *, expected=None) -> bool:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            raw = self._meta_get(conn, self.EVICT_BLOCK_META, {}) or {}
            if expected is not None and raw.get(str(asset_id)) != expected:
                return False
            hit = str(asset_id) in raw
            raw.pop(str(asset_id), None)
            self._meta_set(conn, self.EVICT_BLOCK_META, raw)
            if hit:
                self._event(conn, None, "EVICT_UNBLOCKED", "manual", {"asset_id": asset_id})
        return hit

    ARCHIVE_BLOCK_META = "archive_blocked"

    def archive_blocks(self, max_age_days: float | None = None) -> dict[str, dict[str, Any]]:
        """Pages whose archive was refused *deterministically* by the archiver's
        consistency/snapshot gates (REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT,
        REFUSE_GIT_PARTIAL_ROOT, ...).

        <date> root cause (agent-a+agent-d): the full maintenance pass always archived
        ``plan()[0]``.  ``/home/user/sim-env`` (leveldb cache inside a venv) sat at the
        head of the queue and was refused on <time>, so every pass
        burned its single archive slot on it and zero pages reached Baidu while
        ARCHIVE_CANDIDATE grew 767 -> 821.  Blocked keys are skipped by the archive drain
        and expire after ``max_age_days`` so a page fixed in place is retried without a
        manual unblock.
        """
        with self.connect() as conn:
            raw = self._meta_get(conn, self.ARCHIVE_BLOCK_META, {}) or {}
        if not isinstance(raw, dict):
            return {}
        if max_age_days is None:
            return raw
        cutoff = time.time() - float(max_age_days) * 86400
        now = time.time()
        return {key: value for key, value in raw.items()
                if float((value or {}).get("at") or 0) >= cutoff
                and ("retry_at" not in value or float(value["retry_at"]) > now)}

    def block_archive(self, workspace_key: str, reason: str,
                      retry_after_sec: float | None = None) -> dict[str, Any]:
        if retry_after_sec is not None and retry_after_sec <= 0:
            raise PagerRefused("REFUSE_ARCHIVE_RETRY_INTERVAL")
        now = time.time()
        with self.connect() as conn:
            raw = self._meta_get(conn, self.ARCHIVE_BLOCK_META, {}) or {}
            previous = raw.get(str(workspace_key)) or {}
            raw[str(workspace_key)] = {
                "reason": str(reason)[:500], "at": now,
                "count": int(previous.get("count") or 0) + 1,
            }
            if retry_after_sec is not None:
                raw[str(workspace_key)]["retry_at"] = now + retry_after_sec
            self._meta_set(conn, self.ARCHIVE_BLOCK_META, raw)
            self._event(conn, None, "ARCHIVE_BLOCKED", str(reason)[:500],
                        {"workspace_key": workspace_key})
        return raw[str(workspace_key)]

    def unblock_archive(self, workspace_key: str) -> bool:
        with self.connect() as conn:
            raw = self._meta_get(conn, self.ARCHIVE_BLOCK_META, {}) or {}
            hit = str(workspace_key) in raw
            raw.pop(str(workspace_key), None)
            self._meta_set(conn, self.ARCHIVE_BLOCK_META, raw)
            if hit:
                self._event(conn, None, "ARCHIVE_UNBLOCKED", "manual",
                            {"workspace_key": workspace_key})
        return hit

    def eviction_candidates(self, hot_days: float | None = None,
                            cold_days: float | None = None) -> list[dict[str, Any]]:
        """Pages evictable *under pressure*, coldest first.

        <date> contract fix: pressure candidacy floors at ``hot_days`` (the hot-grace
        window), not ``cold_days``. ``pressure_waiting()`` already promised
        ``eligible_at = last_access + hot_days``; but this method used the calm-state
        15-day schedule, so a fully-proven page aged 3..15 days was neither a candidate
        nor "waiting" -- batch-0002 (~80GB) sat invisible for 18h while the pool stayed
        at 8% free.

        <date>: the calm-state schedule now floors at ``hot_days`` too (the 15-day
        cooling is retired), so this override no longer diverges from ``plan()``.  The
        argument is kept so a caller can still widen the window deliberately.
        """
        hot = float(self.policy.get("hot_days", 3) if hot_days is None else hot_days)
        plan = self.plan(hot, hot if cold_days is None else float(cold_days))
        # Incident note: was ``self.eviction_blocks()`` -- the unbounded ledger, i.e.
        # a permanent blacklist.  Now bounded by ``evict_block_days`` exactly like the
        # archive drain bounds itself with ``archive_block_days``; an expired refusal
        # returns here to be re-judged, and the predicates re-block it if it still fails.
        # Optional policy key on purpose: adding it to the required set would make every
        # existing policy file fail-closed on load (same reasoning as
        # ``isolation_err_free_ratio``, added earlier today).
        blocked = self.eviction_blocks(float(self.policy.get("evict_block_days", 7)))
        rows = [row for row in plan if row["storage_pool"] == "MANAGED"
                and row["action"] == "EVICT_CANDIDATE" and row.get("asset_id")
                and row["asset_id"] not in blocked]
        rows.sort(key=lambda row: (
            row.get("last_access") or 0, row.get("access_count") or 0,
            row["workspace_key"],
        ))
        return rows

    def pressure_waiting(self, hot_days: float | None = None) -> list[dict[str, Any]]:
        """Fully-proven MANAGED pages held back from eviction only by hot grace or a lease.

        Under pressure with zero candidates this separates "waiting for the
        institution's own cooling window" (a page proven cloud+snapshot,
        classified, local, unpinned, but still inside ``hot_days`` or leased) from
        a genuinely stuck pool with nothing provable to evict.
        """
        hot = float(self.policy.get("hot_days", 3) if hot_days is None else hot_days)
        now = time.time()
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM pages WHERE storage_pool='MANAGED' AND local_present=1
                AND pinned=0 AND cloud_asset_id IS NOT NULL AND cloud_verified=1
                AND snapshot_verified=1 AND dirty=0
                AND annotation_status='CURRENT' AND redundancy_class!='UNCLASSIFIED'"""
            ).fetchall()
        out = []
        for row in rows:
            minimum = MIN_INDEPENDENT_COPIES.get(row["redundancy_class"])
            if minimum is None or int(row["independent_copies"]) < minimum:
                continue
            anchor_epoch = float(row["last_access"] or row["updated_at"])
            leased = bool(row["lease_until"] and row["lease_until"] > now)
            in_grace = (now - anchor_epoch) / 86400 < hot
            if not (leased or in_grace):
                continue
            eligible_at = max(anchor_epoch + hot * 86400,
                              float(row["lease_until"] or 0))
            out.append({
                "asset_id": row["cloud_asset_id"], "workspace_key": row["workspace_key"],
                "host": row["host"], "path": row["path"],
                "size_bytes": int(row["size_bytes"] or 0),
                "reason": "lease" if leased else "hot_grace",
                "eligible_at": eligible_at,
            })
        out.sort(key=lambda item: item["eligible_at"])
        return out

    def mark_evicted(self, asset_id: str, evidence: str) -> int:
        now = time.time()
        with self.connect() as conn:
            cur = conn.execute(
                """UPDATE pages SET local_present=0,state='COLD',lease_until=NULL,
                reason=?,updated_at=? WHERE cloud_asset_id=? AND storage_pool='MANAGED'""",
                (evidence, now, asset_id),
            )
            self._event(conn, None, "EVICTED", evidence, {"asset_id": asset_id})
            return cur.rowcount

    def relocate_asset(self, asset_id: str, host: str, path: str,
                       evidence: str, *, local_present: int = 0,
                       verified_absent_paths: Iterable[str] | None = None,
                       verified_snapshot: bool = False) -> dict[str, Any]:
        """Atomically move one logical asset page to its new physical-pool path."""
        host = _host_name(host)
        path = os.path.normpath(path)
        if not os.path.isabs(path):
            raise PagerRefused("REFUSE_RELOCATE_RELATIVE_PATH")
        storage_pool = storage_pool_for(host, path, self.policy)
        if storage_pool != "MANAGED":
            raise PagerRefused(
                f"REFUSE_RELOCATE_TARGET_NOT_MANAGED host={host} path={path}"
            )
        new_key = self.key(host, path)
        now = time.time()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pages WHERE cloud_asset_id=?", (asset_id,)
            ).fetchall()
            if len(rows) != 1:
                targets = [row for row in rows if row["workspace_key"] == new_key]
                stale = [row for row in rows if row["workspace_key"] != new_key]
                allowed = {
                    os.path.normpath(str(value))
                    for value in (verified_absent_paths or [])
                }
                stale_paths = {os.path.normpath(row["path"]) for row in stale}
                if (int(local_present) != 0 or len(targets) != 1
                        or not stale or allowed != stale_paths):
                    raise PagerRefused(
                        f"REFUSE_RELOCATE_ASSET_ROW_COUNT asset={asset_id} count={len(rows)}"
                    )
                for row in stale:
                    conn.execute(
                        "DELETE FROM pages WHERE workspace_key=?", (row["workspace_key"],)
                    )
                old = targets[0]
                self._event(conn, new_key, "ASSET_RELOCATE_COALESCED", evidence, {
                    "asset_id": asset_id,
                    "verified_absent_paths": sorted(stale_paths),
                })
            else:
                old = rows[0]
            conflict = conn.execute(
                "SELECT cloud_asset_id FROM pages WHERE workspace_key=?", (new_key,)
            ).fetchone()
            if conflict and new_key != old["workspace_key"]:
                raise PagerRefused(
                    f"REFUSE_RELOCATE_TARGET_CONFLICT asset={conflict[0]} path={path}"
                )
            state = "COLD" if local_present == 0 else "HOT"
            dirty = 0 if verified_snapshot else old["dirty"]
            cloud_verified = 1 if verified_snapshot else old["cloud_verified"]
            restore_verified = 1 if verified_snapshot else old["restore_verified"]
            snapshot_verified = 1 if verified_snapshot else old["snapshot_verified"]
            conn.execute(
                """UPDATE pages SET workspace_key=?,host=?,path=?,storage_pool=?,
                local_present=?,state=?,dirty=?,cloud_verified=?,restore_verified=?,
                snapshot_verified=?,lease_until=NULL,reason=?,updated_at=?
                WHERE workspace_key=?""",
                (new_key, host, path, storage_pool, int(local_present), state, dirty,
                 cloud_verified, restore_verified, snapshot_verified, evidence, now,
                 old["workspace_key"]),
            )
            self._event(conn, new_key, "ASSET_RELOCATED", evidence, {
                "asset_id": asset_id, "old_key": old["workspace_key"],
                "new_key": new_key, "local_present": int(local_present),
                "verified_snapshot": bool(verified_snapshot),
            })
            return dict(conn.execute(
                "SELECT * FROM pages WHERE workspace_key=?", (new_key,)
            ).fetchone())

    def alerts(self, disk_stats: dict[str, dict[str, Any]] | None = None,
               now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        pools = self.pool_status(disk_stats=disk_stats, update_hysteresis=True)
        managed, isolated = pools["managed"], pools["isolated"]
        out = []
        if isolated["free_ratio"] < isolated["warn_free_ratio"]:
            # 两级。err 是唯一能穿透用户 ack 的形态,也是 roles_watchdog 跳过
            # 通用 hostb.disk_data DISK_HIGH 检查之后,这个池仅剩的上屏路径。
            err_line = float(isolated.get("err_free_ratio",
                                          DEFAULT_ISOLATION_ERR_FREE_RATIO))
            critical = isolated["free_ratio"] < err_line
            out.append({"level": "err" if critical else "warn",
                        "code": "PAGER_ISOLATION_LOW",
                        "text": "隔离池快写满了" if critical else "隔离池空间接近上限",
                        "detail": "free_ratio=%.4f warn_below=%.4f err_below=%.4f"
                        % (isolated["free_ratio"], isolated["warn_free_ratio"],
                           err_line)})
        candidates = self.eviction_candidates()
        blocked = self.eviction_blocks()
        if managed["eviction_active"]:
            if candidates:
                out.append({"level": "warn", "code": "PAGER_EVICTING",
                            "text": "主盘低水位，正在淘汰温盘",
                            "detail": "free_ratio=%.4f target=%.2f candidates=%d bytes_to_stop=%d blocked=%d"
                            % (managed["free_ratio"], managed["stop_free_ratio"],
                               len(candidates), managed["bytes_to_stop"], len(blocked))})
            else:
                waiting = self.pressure_waiting()
                if waiting:
                    soonest = waiting[0]
                    out.append({"level": "warn", "code": "PAGER_PRESSURE_WAITING",
                                "text": "主盘低水位，已证明页仍在热度保护期，到期自动淘汰",
                                "detail": "free_ratio=%.4f target=%.2f waiting=%d next=%s "
                                          "reason=%s eligible_at=%s bytes=%d"
                                % (managed["free_ratio"], managed["stop_free_ratio"],
                                   len(waiting), soonest["asset_id"], soonest["reason"],
                                   time.strftime("%Y-%m-%dT%H:%M:%S",
                                                 time.localtime(soonest["eligible_at"])),
                                   soonest["size_bytes"])})
                else:
                    blocked_note = ""
                    if blocked:
                        blocked_note = " blocked=%d(%s)" % (len(blocked), ",".join(
                            "%s:%s" % (k, (v.get("reason") or "")[:60])
                            for k, v in sorted(blocked.items())[:3]))
                    if managed.get('capacity_pending'):
                        out.append({'level': 'err', 'code': 'PAGER_PRESSURE_STUCK',
                                    'text': '下载等待空间，无符合条件的温盘可回收',
                                    'detail': 'capacity_gap_bytes=%d target_free_bytes=%d%s' % (
                                        managed['capacity_gap_bytes'], managed['target_free_bytes'], blocked_note)})
                    elif managed["free_ratio"] >= managed["trigger_free_ratio"]:
                        # <date>: hysteresis keeps eviction "active" until the stop
                        # watermark, but being back above the trigger line with nothing
                        # provable left to evict is a drained pool, not a stuck one.
                        out.append({"level": "warn", "code": "PAGER_PRESSURE_DRAINED",
                                    "text": "主盘已回到触发线上方但未达停止线，无可淘汰页",
                                    "detail": "free_ratio=%.4f trigger=%.2f target=%.2f eligible_warm=0 waiting=0%s"
                                    % (managed["free_ratio"], managed["trigger_free_ratio"],
                                       managed["stop_free_ratio"], blocked_note)})
                    else:
                        out.append({"level": "err", "code": "PAGER_PRESSURE_STUCK",
                                    "text": "主盘淘汰后仍未恢复水位",
                                    "detail": "free_ratio=%.4f target=%.2f eligible_warm=0 waiting=0%s"
                                    % (managed["free_ratio"], managed["stop_free_ratio"],
                                       blocked_note)})
        if managed["known_hot_bytes"] > managed["usable_bytes"]:
            out.append({"level": "err", "code": "PAGER_HOT_OVER_CAP",
                        "text": "热盘自身超过可管理上限",
                        "detail": "known_hot=%d usable=%d" % (
                            managed["known_hot_bytes"], managed["usable_bytes"])})
        stale_after = float(self.policy.get("semantic_stale_alert_after_sec", 1800))
        with self.connect() as conn:
            stale = conn.execute(
                "SELECT count(*) FROM pages WHERE annotation_status!='CURRENT' "
                "AND coalesce(semantic_stale_at,updated_at)<=?",
                (now - stale_after,),
            ).fetchone()[0]
        if stale:
            out.append({"level": "warn", "code": "PAGER_SEMANTIC_STALE",
                        "text": "语义标注陈旧或索引同步失败",
                        "detail": f"pages={int(stale)} grace_sec={int(stale_after)}"})
        return out

    def requirements_from_text(self, text: str, assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        needs = []
        for asset in assets:
            asset_id, original = asset["asset_id"], asset["original_path"]
            asset_hit = bool(re.search(
                r"(?<![A-Za-z0-9_-])" + re.escape(asset_id) + r"(?![A-Za-z0-9_-])", text
            ))
            path_hit = bool(original and re.search(
                re.escape(original.rstrip("/")) + r"(?=$|[\s'\"`),;\]}])", text
            ))
            explicit = asset_hit or path_hit
            if not explicit:
                continue
            local_present = os.path.exists(original) if asset["host"] == "mac" else None
            needs.append({
                "asset_id": asset_id, "host": asset["host"], "original_path": original,
                "cloud_verified": asset["cloud_verified"],
                "local_present": local_present,
                "needs_restore": bool(asset["cloud_verified"] and local_present is False),
            })
        return needs

    def search_asset_files(self, keywords: Iterable[str], limit: int = 100) -> list[dict[str, Any]]:
        terms = [str(x).casefold() for x in keywords if str(x).strip()]
        if not terms:
            return []
        with self.connect() as conn:
            long_terms = [x for x in terms if len(x) >= 3]
            short_terms = [x for x in terms if len(x) < 3]
            if self._asset_fts_exists(conn) and long_terms:
                match = " AND ".join(
                    '"%s"' % term.replace('"', '""') for term in long_terms
                )
                short_where = "".join(
                    " AND lower(af.relative_path) LIKE ?" for _ in short_terms
                )
                params = [match] + ["%%%s%%" % term for term in short_terms] + [int(limit)]
                rows = conn.execute(
                    "SELECT af.asset_id,af.relative_path,af.size_bytes,af.mtime_ns,"
                    "bm25(asset_files_fts) AS fts_rank "
                    "FROM asset_files_fts JOIN asset_files AS af "
                    "ON af.source_path=asset_files_fts.source_path "
                    "AND af.relative_path=asset_files_fts.relative_path "
                    "WHERE asset_files_fts MATCH ?%s "
                    "ORDER BY fts_rank,length(af.relative_path),af.relative_path LIMIT ?"
                    % short_where,
                    params,
                ).fetchall()
                return [{**dict(r), "search_backend": "fts5"} for r in rows]
            where = " AND ".join("lower(relative_path) LIKE ?" for _ in terms)
            params = ["%%%s%%" % term for term in terms] + [int(limit)]
            rows = conn.execute(
                "SELECT asset_id,relative_path,size_bytes,mtime_ns FROM asset_files "
                "WHERE %s ORDER BY length(relative_path),relative_path LIMIT ?" % where,
                params,
            ).fetchall()
        return [{**dict(r), "search_backend": "like_fallback"} for r in rows]


def restore_version_identity(asset: dict[str, Any]) -> str:
    asset_id = asset["asset_id"]
    try:
        if asset.get("vault") == "v3":
            with CLOUD_CATALOG.open(encoding="utf-8") as catalog:
                rows = (json.loads(line) for line in catalog if line.strip())
                row = next(row for row in rows if row.get("asset_id") == asset_id)
            if not row.get("current_version_id"):
                raise ValueError("missing native version")
            identity = [asset_id, "v3", row["current_version_id"], row.get("snapshot_sha256")]
        else:
            heads_path = CLOUD_WORKSPACE / "vault_v2_heads.json"
            if heads_path.is_file():
                head = json.loads(heads_path.read_text(encoding="utf-8"))["heads"][asset_id]
                if not re.fullmatch(r"[0-9a-f]{64}", str(head.get("version_id") or "")):
                    raise ValueError("invalid current version")
                identity = [asset_id, "v2", head["version_id"], head.get("root")]
            else:
                with (CLOUD_WORKSPACE / "vault_v2_ledger.tsv").open(encoding="utf-8") as ledger:
                    rows = [row for row in csv.reader(ledger, delimiter="\t")
                            if len(row) == 12 and row[2] == asset_id]
                if not rows:
                    raise ValueError("missing legacy version evidence")
                identity = [asset_id, "legacy", rows]
        return hashlib.sha256(json.dumps(identity, sort_keys=True,
                                         ensure_ascii=False).encode("utf-8")).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise PagerRefused("REFUSE_RESTORE_VERSION_UNAVAILABLE asset=%s" % asset_id) from error


def restore_asset(asset: dict[str, Any], output_root: Path = PAGE_CACHE,
                  timeout: float = 24 * 3600) -> Path:
    if not asset.get("cloud_verified"):
        raise PagerRefused(f"REFUSE_ASSET_NOT_CLOUD_CONFIRMED {asset.get('asset_id')}")
    if not RESTORE_TOOL.is_file():
        raise PagerRefused(f"REFUSE_RESTORE_TOOL_MISSING {RESTORE_TOOL}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(asset.get("asset_id") or "")):
        raise PagerRefused("REFUSE_UNSAFE_RESTORE_ASSET_ID")
    identity = restore_version_identity(asset)
    output_root.mkdir(parents=True, exist_ok=True)
    final = output_root / asset["asset_id"]
    marker = output_root / (".restore-%s.json" % asset["asset_id"])
    if final.is_symlink() or marker.is_symlink():
        raise PagerRefused("REFUSE_RESTORE_CACHE_SYMLINK")
    if final.exists():
        try:
            proof = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise PagerRefused(f"REFUSE_UNPROVEN_RESTORE_CACHE {final}")
        if (proof.get("asset_id") != asset["asset_id"] or proof.get("verdict") != "RESTORE_PASS"
                or proof.get("output") != str(final)):
            raise PagerRefused(f"REFUSE_BAD_RESTORE_CACHE_PROOF {marker}")
        if proof.get("version_fingerprint") == identity:
            return final
        discard_restore_cache(asset["asset_id"], output_root)
    # <date>: ``--purge-downloaded-parts`` is not an optimisation here, it is
    # the difference between one and two full copies of the asset on this volume.
    # Without it the encrypted blobs stay in the Baidu staging directory *and*
    # the plaintext lands in the page cache: a 19.4GB engine held 34GB of Mac
    # disk, which is how the volume reached zero free bytes and every tool on the
    # host lost the ability to create a temp file.  With it, at most one blob is
    # resident while the plaintext streams into the tar.
    proc = subprocess.run(
        [restore_python(), str(RESTORE_TOOL), asset["asset_id"], "--download",
         "--purge-downloaded-parts", "--output", str(output_root)],
        text=True, capture_output=True, timeout=timeout,
    )
    if proc.returncode != 0 or not final.exists():
        tail = (proc.stdout + "\n" + proc.stderr)[-4000:]
        raise PagerRefused(
            f"REFUSE_ASSET_RESTORE_FAILED asset={asset['asset_id']} rc={proc.returncode} tail={tail}"
        )
    tmp = marker.with_suffix(marker.suffix + ".tmp.%d" % os.getpid())
    tmp.write_text(json.dumps({
        "asset_id": asset["asset_id"], "verdict": "RESTORE_PASS",
        "restored_at": time.time(), "output": str(final),
        "version_fingerprint": None,
    }, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, marker)
    try:
        if restore_version_identity(asset) != identity:
            raise PagerRefused("REFUSE_RESTORE_VERSION_CHANGED_DURING_TRANSFER")
    except PagerRefused:
        discard_restore_cache(asset["asset_id"], output_root)
        raise
    proof = json.loads(marker.read_text(encoding="utf-8"))
    proof["version_fingerprint"] = identity
    tmp.write_text(json.dumps(proof, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, marker)
    return final


def record_restore_test(asset_id: str, evidence: str,
                        restore_tests_path: Path = RESTORE_TESTS) -> None:
    """Persist a real cloud-download/decrypt/tar PASS for future pager syncs."""
    restore_tests_path.parent.mkdir(parents=True, exist_ok=True)
    restore_tests_path.touch(mode=0o600, exist_ok=True)
    with restore_tests_path.open("a", encoding="utf-8", newline="") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        csv.writer(handle, delimiter="\t", lineterminator="\n").writerow([
            asset_id, datetime.now().astimezone().isoformat(timespec="seconds"),
            "baidu_native_download_decrypt_tar", "PASS", evidence,
        ])
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle, fcntl.LOCK_UN)


def discard_restore_cache(asset_id: str, output_root: Path = PAGE_CACHE) -> None:
    """Delete only the verified disposable page cache, never an original path."""
    root = output_root.resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", asset_id):
        raise PagerRefused("REFUSE_UNSAFE_CACHE_ASSET_ID")
    final = root / asset_id
    marker = output_root / (".restore-%s.json" % asset_id)
    if final.is_symlink() or marker.is_symlink() or final.parent != root:
        raise PagerRefused(f"REFUSE_CACHE_DELETE_OUTSIDE_ROOT {final}")
    if final.exists():
        try:
            proof = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise PagerRefused("REFUSE_UNPROVEN_CACHE_DELETE") from error
        if (proof.get("asset_id") != asset_id or proof.get("verdict") != "RESTORE_PASS"
                or Path(proof.get("output") or "").resolve() != final):
            raise PagerRefused("REFUSE_BAD_CACHE_DELETE_PROOF")

        def repair_directory(operation, failed_path, error_info):
            target = Path(failed_path)
            metadata = target.lstat()
            if (not isinstance(error_info[1], PermissionError) or target.is_symlink()
                    or not target.resolve().is_relative_to(final)
                    or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()):
                raise error_info[1]
            os.chmod(target, stat.S_IMODE(metadata.st_mode) | stat.S_IRWXU,
                     follow_symlinks=False)
            if operation in (os.open, os.scandir):
                shutil.rmtree(target, onerror=repair_directory)
            else:
                operation(target)

        shutil.rmtree(final, onerror=repair_directory)
    marker.unlink(missing_ok=True)


def find_asset(assets: Iterable[dict[str, Any]], asset_id: str) -> dict[str, Any]:
    hits = [a for a in assets if a.get("asset_id") == asset_id]
    if len(hits) != 1:
        raise PagerRefused(f"REFUSE_ASSET_COUNT asset={asset_id} count={len(hits)}")
    return hits[0]
