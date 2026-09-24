#!/usr/bin/env python3
"""Copy one cold Workspace Pager page into the existing opaque Baidu vault.

The command refuses pinned/hot pages, active workers, open file descriptors,
broad roots and concurrent vault writers.  Cloud confirmation is written only
after pre/post metadata snapshots match.  Source deletion is not implemented.
"""
from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import hashlib
import json
import os
import platform
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

def _coldstore_bin() -> Path:
    env = os.environ.get("COLDSTORE_BIN")
    if env:
        return Path(env).expanduser()
    user = Path.home() / ".coldstore/bin"
    if (user / "ws").exists():
        return user
    return Path(__file__).resolve().parent.parent / "pager"  # in-repo sibling layout


COLDSTORE_BIN = _coldstore_bin()
if str(COLDSTORE_BIN) not in sys.path:
    sys.path.insert(0, str(COLDSTORE_BIN))
from workspace_consistency import ConsistencyRefused, inspect_workspace

WS = Path(__file__).resolve().parent
PAGER_DB = Path.home() / ".coldstore/state/workspace_pages.db"
STREAM = WS / "vault_v2_stream.py"
CATALOG = WS / "cloud_asset_catalog.py"
SYNC = WS / "vault_v2_sync.py"
VERSIONS = WS / "vault_v2_versions.py"
SOURCES = WS / "vault_v2_sources.tsv"
ROOTS = WS / "vault_v2_roots.tsv"
PROOFS = WS / "workspace_snapshot_proofs.tsv"
LOCK = WS / ".workspace_archive.lock"
REMOTE = os.environ.get("COLDSTORE_REMOTE", "user@host-b")
# 同一份文件在两台机器上运行,本机判据必须动态取,不能写死 "mac"。
SELF_HOST = "mac" if platform.system() == "Darwin" else "hostb"
REMOTE_HELPER = "/home/user/.coldstore/bin/workspace_archive_remote.py"
DENIED_ROOTS = {
    "/", "/Users", "/Users/user", "/home", "/home/user",
    str(Path.home() / ".coldstore"), str(WS),
}


class ArchiveRefused(RuntimeError):
    pass


# Incident note: per-page fixed overhead dominated the archive drain — a
# 1.7MB page took 2m34s wall.  These probes attribute the wall clock to each
# phase so the drain can be optimised against measurements, not guesses.
# Purely additive: a probe failure must never change archive behaviour.
PHASE_TIMING = WS / "archive_phase_timing.jsonl"
_PHASES: list[dict] = []
_CTX: dict = {}


class phase:
    """Context manager recording the wall time of one archive phase."""

    def __init__(self, name):
        self.name = name
        self.t0 = None

    def __enter__(self):
        self.t0 = time.time()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            _PHASES.append({"phase": self.name,
                            "sec": round(time.time() - self.t0, 3),
                            "failed": exc_type is not None})
        except Exception:
            pass
        return False


def flush_phase_timing(host, path, label, outcome, size_bytes=None):
    """Append one timing row.  Never raises: timing must not break archiving."""
    try:
        if not _PHASES:
            return
        row = {"at": now_iso(), "host": host, "path": path, "asset_id": label,
               "outcome": outcome, "size_bytes": size_bytes,
               "total_sec": round(sum(p["sec"] for p in _PHASES), 3),
               "phases": _PHASES}
        with PHASE_TIMING.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdin=subprocess.DEVNULL, **kwargs)


def canonical_host(value):
    low = value.casefold()
    if low in {"mac", "host-a", "host-a"}:
        return "mac"
    if low in {"hostb", "linux"}:
        return "hostb"
    raise ArchiveRefused(f"REFUSE_BAD_HOST {value}")


def validate_target(host, raw_path):
    path = os.path.normpath(raw_path)
    if not os.path.isabs(path) or path in DENIED_ROOTS:
        raise ArchiveRefused(f"REFUSE_BROAD_OR_RELATIVE_PATH {raw_path}")
    home = "/Users/user" if host == "mac" else "/home/user"
    owned = path.startswith(home + "/") or (host == "hostb" and path.startswith("/data/"))
    if not owned:
        raise ArchiveRefused(f"REFUSE_PATH_OUTSIDE_OWNED_ROOT host={host} path={path}")
    return path


def asset_label(host, path):
    slug = re.sub(r"[^a-z0-9]+", "-", Path(path).name.casefold()).strip("-")[:28]
    digest = hashlib.sha256((host + "\0" + path).encode()).hexdigest()[:16]
    return f"ws-{host}-{slug or 'workspace'}-{digest}"


def _snapshot_local(path):
    path = Path(path)
    if not path.exists() or path.is_symlink():
        raise ArchiveRefused(f"REFUSE_MISSING_OR_SYMLINK_ROOT {path}")
    h = hashlib.sha256()
    count = total = 0

    def add(full, rel):
        nonlocal count, total
        st = full.lstat()
        if full.is_symlink():
            kind, extra = "l", os.readlink(full)
        elif full.is_dir():
            kind, extra = "d", ""
        elif full.is_file():
            kind, extra = "f", ""
            total += st.st_size
        else:
            kind, extra = "o", ""
        row = [rel, kind, st.st_mode, st.st_size, st.st_mtime_ns, extra]
        h.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
        h.update(b"\n")
        count += 1

    if path.is_file():
        add(path, path.name)
    else:
        add(path, ".")
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
            dirs.sort(); files.sort()
            base = Path(root)
            for name in dirs + files:
                full = base / name
                add(full, str(full.relative_to(path)))
    return {"sha256": h.hexdigest(), "entries": count, "bytes": total}


def snapshot(host, path):
    if host == "mac":
        return _snapshot_local(path)
    encoded = base64.b64encode(path.encode()).decode()
    proc = subprocess.run(
        ["ssh", "-n", REMOTE, "sudo", "-n", REMOTE_HELPER,
         "snapshot", "--path-b64", encoded],
        text=True, capture_output=True, timeout=3600)
    if proc.returncode:
        raise ArchiveRefused(f"REFUSE_REMOTE_SNAPSHOT rc={proc.returncode} detail={proc.stderr[-1000:]}")
    return json.loads(proc.stdout)


def consistency(host, path):
    if host == "mac":
        try:
            return inspect_workspace(path)
        except ConsistencyRefused as exc:
            raise ArchiveRefused(str(exc)) from exc
    encoded = base64.b64encode(path.encode()).decode()
    proc = subprocess.run(
        ["ssh", "-n", REMOTE, "sudo", "-n", REMOTE_HELPER,
         "consistency", "--path-b64", encoded],
        text=True, capture_output=True, timeout=3600)
    if proc.returncode:
        raise ArchiveRefused(
            f"REFUSE_REMOTE_CONSISTENCY rc={proc.returncode} detail={proc.stderr[-2000:]}"
        )
    return json.loads(proc.stdout)


def assert_no_open_handles(host, path):
    if host == "mac":
        try:
            proc = subprocess.run(["/usr/sbin/lsof", "+D", path], text=True,
                                  capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise ArchiveRefused(f"REFUSE_LSOF_TIMEOUT {path}") from exc
        hits = [x for x in proc.stdout.splitlines()[1:] if x.strip()]
    else:
        encoded = base64.b64encode(path.encode()).decode()
        proc = subprocess.run(
            ["ssh", "-n", REMOTE, "sudo", "-n", REMOTE_HELPER,
             "open-fds", "--path-b64", encoded],
            text=True, capture_output=True, timeout=60)
        if proc.returncode:
            raise ArchiveRefused(f"REFUSE_REMOTE_FD_SCAN rc={proc.returncode}")
        hits = json.loads(proc.stdout)
    if hits:
        raise ArchiveRefused(f"REFUSE_OPEN_HANDLES count={len(hits)} sample={hits[:3]}")


def _running_refs_local(root, path):
    hits = []
    running = Path(root) / "running"
    if not running.is_dir():
        return hits
    for job in running.iterdir():
        if not job.is_dir():
            continue
        text = ""
        for name in ("task.json", "prompt.md"):
            try:
                text += (job / name).read_text(encoding="utf-8", errors="replace") + "\n"
            except OSError:
                pass
        if path in text:
            hits.append(job.name)
    return hits


def assert_no_running_worker(host, path):
    if host == "mac":
        hits = _running_refs_local(Path.home() / ".coldstore/dispatch", path)
    else:
        encoded = base64.b64encode(path.encode()).decode()
        proc = subprocess.run(["ssh", "-n", REMOTE, REMOTE_HELPER,
                               "running-refs", "--path-b64", encoded],
                              text=True, capture_output=True, timeout=30)
        if proc.returncode:
            raise ArchiveRefused(f"REFUSE_REMOTE_WORKER_SCAN rc={proc.returncode}")
        hits = json.loads(proc.stdout)
    if hits:
        raise ArchiveRefused(f"REFUSE_ACTIVE_WORKER tasks={hits[:20]}")


# 与 workspace_pager._LIVENESS_PROBE_SH 同款判据,刻意保持一致:两处用不同的
# 时钟,同一棵树是冷是热就会取决于你问哪个组件。-print -quit 命中即短路,活树
# ~0ms,真冷的 80GB 树 ~40ms。
_LIVENESS_SH = (
    'if [ ! -e "$1" ]; then echo M; exit 0; fi\n'
    'h=$(find "$1" -type f -newermt "-$2 days" -print -quit 2>/dev/null)\n'
    'if [ -n "$h" ]; then echo 1; else echo 0; fi\n'
)


def probe_tree_recent(host, path, window_days):
    """该树内是否存在 window_days 天内被修改的文件?

    返回 1(活跃) / 0(冷) / None(不存在或探测失败)。None 必须由调用方
    fail-closed,不得当成冷。
    """
    window = str(int(max(1, float(window_days))))
    argv = ["bash", "-s", "--", str(path), window]
    # Run locally whenever the page lives on this machine; the same file is used
    # on both hosts, so a hardcoded "mac" test would make the hostb copy ssh to
    # itself for every probe.
    if host != SELF_HOST:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
                REMOTE, "bash -s -- " + shlex.quote(str(path)) + " " + window]
    try:
        proc = subprocess.run(argv, input=_LIVENESS_SH, text=True,
                              capture_output=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return {"1": 1, "0": 0}.get(proc.stdout.strip().splitlines()[-1].strip()
                                if proc.stdout.strip() else "")


def assert_tree_not_live(host, path, window_days, probe=probe_tree_recent):
    """归档前的实时冷度闸。

    require_cold_page 只看 last_access,而它取自 HANDOFF.md 的 mtime 且注册后
    冻结 —— 一个 HANDOFF 没动的忙工作区会永远显示"很老"。plan() 侧虽有
    tree_recent,但那是最长 6 小时的缓存,产线在窗口内的新写入完全不可见。
    归档是纯上传成本:传一个正在变的树,事后快照校验必失败并要求重传。
    """
    answer = probe(host, path, window_days)
    if answer is None:
        raise ArchiveRefused(
            f"REFUSE_PAGE_LIVENESS_UNKNOWN host={host} path={path}")
    if answer == 1:
        raise ArchiveRefused(
            f"REFUSE_PAGE_TREE_LIVE host={host} path={path} "
            f"window_days={window_days}")


def require_cold_page(host, path, cold_days):
    if not PAGER_DB.is_file():
        raise ArchiveRefused(f"REFUSE_PAGER_DB_MISSING {PAGER_DB}")
    key = f"{host}|{path.rstrip('/') or '/'}"
    with sqlite3.connect(f"file:{PAGER_DB}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM pages WHERE workspace_key=?", (key,)).fetchone()
    if row is None:
        raise ArchiveRefused(f"REFUSE_PAGE_UNKNOWN {key}")
    data = dict(row)
    age = (time.time() - (data.get("last_access") or data["updated_at"])) / 86400
    if data["pinned"] or (data.get("lease_until") or 0) > time.time():
        raise ArchiveRefused(f"REFUSE_PAGE_HOT_OR_PINNED key={key}")
    if age < cold_days:
        raise ArchiveRefused(f"REFUSE_PAGE_TOO_RECENT age_days={age:.3f} cold_days={cold_days}")
    # last_access 说"老"还不够:它是冻结的 HANDOFF mtime。真正动手前必须拿
    # 一次实时的文件系统证据,否则会把正在被写的产物目录传上云。
    assert_tree_not_live(host, path, cold_days)
    data["age_days"] = age
    return data


def assert_no_other_vault_writer():
    # The Baidu folder-backup watcher is single-writer by contract: <date>
    # measured 3x178MB staged together at 0.28MB/s aggregate vs 3.27MB/s serial,
    # and the third file never registered.  A live v3 uploader counts as a writer.
    # Detection lives in vault_v2_stream.vault_writer_busy (lock probe + python-only
    # pgrep); our own archiver lock is excluded because we hold it while executing.
    from vault_v2_stream import vault_writer_busy  # same directory
    busy = vault_writer_busy(exclude=(LOCK,))
    if busy:
        raise ArchiveRefused("REFUSE_VAULT_WRITER_BUSY " + busy)


def append_row(path, row):
    path.touch(mode=0o600, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        csv.writer(handle, delimiter="\t", lineterminator="\n").writerow(row)
        handle.flush(); os.fsync(handle.fileno()); fcntl.flock(handle, fcntl.LOCK_UN)


def source_known(label, path):
    try:
        with SOURCES.open(encoding="utf-8") as handle:
            return any(len(r) >= 4 and r[2] == path and r[3] == label
                       for r in csv.reader(handle, delimiter="\t"))
    except OSError:
        return False


def tar_process(host, path):
    parent, base = os.path.dirname(path), os.path.basename(path)
    if host == "mac":
        return subprocess.Popen(["/usr/bin/tar", "-C", parent, "-cf", "-", "--", base],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(os.environ, COPYFILE_DISABLE="1"))
    encoded = base64.b64encode(path.encode()).decode()
    return subprocess.Popen(["ssh", "-n", REMOTE, "sudo", "-n", REMOTE_HELPER,
                             "tar", "--path-b64", encoded],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def execute_archive(host, path, label, description, before, consistency_before):
    with phase("assert_no_other_vault_writer"):
        assert_no_other_vault_writer()
    with phase("source_register"):
        if not source_known(label, path):
            # Incident note: the catalogue/state rebuild that used to run
            # here cost ~15s per page and published a source row that is not yet
            # restorable — cloud_asset_catalog only promotes a label once
            # vault_v2_roots.tsv carries ROOT_CLOUD_CONFIRMED, which is written
            # below.  The post-upload rebuild therefore publishes the same row,
            # and a crash mid-upload leaves the append-only source row on disk
            # for the next sync.  Registering without rebuilding is safe.
            append_row(SOURCES, [now_iso(), "Mac" if host == "mac" else "hostb", path,
                                 label, before["bytes"], description])
    with phase("tar_encrypt_upload"):
        tar = tar_process(host, path)
        assert tar.stdout is not None
        uploader = subprocess.Popen([str(STREAM), "--label", label, "--root", path],
                                    stdin=tar.stdout, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        tar.stdout.close()
        out, upload_err = uploader.communicate()
        tar_err = tar.stderr.read().decode(errors="replace") if tar.stderr else ""
        tar_rc = tar.wait()
        if uploader.returncode or tar_rc:
            raise ArchiveRefused(f"REFUSE_ARCHIVE_PIPE tar_rc={tar_rc} "
                                 f"upload_rc={uploader.returncode} "
                                 f"detail={(tar_err + upload_err + out)[-3000:]}")
    with phase("snapshot_after"):
        after = snapshot(host, path)
    if after != before:
        append_row(ROOTS, [now_iso(), path, label, before["bytes"],
                           "Mac" if host == "mac" else "hostb",
                           "ROOT_CLOUD_INVALIDATED_SNAPSHOT_DRIFT"])
        raise ArchiveRefused(f"REFUSE_SNAPSHOT_DRIFT before={before} after={after}")
    with phase("consistency_after"):
        consistency_after = consistency(host, path)
    if consistency_after != consistency_before:
        append_row(ROOTS, [now_iso(), path, label, before["bytes"],
                           "Mac" if host == "mac" else "hostb",
                           "ROOT_CLOUD_INVALIDATED_CONSISTENCY_DRIFT"])
        raise ArchiveRefused(
            "REFUSE_CONSISTENCY_DRIFT before=%s after=%s"
            % (consistency_before["fingerprint"], consistency_after["fingerprint"])
        )
    append_row(ROOTS, [now_iso(), path, label, before["bytes"],
                       "Mac" if host == "mac" else "hostb", "ROOT_CLOUD_CONFIRMED"])
    with phase("versions_commit"):
        run([str(VERSIONS), "commit", "--asset", label, "--root", path],
            capture_output=True, text=True)
    # Column 12 (<date>): the committed head this snapshot belongs to.  The
    # trust-the-cloud evictor compares the live tree with *this* snapshot and
    # refuses when the proof's version is not the current head.
    try:
        committed_version = str(json.loads((WS / "vault_v2_heads.json").read_text(
            encoding="utf-8"))["heads"][label]["version_id"])
    except (OSError, KeyError, TypeError, ValueError):
        committed_version = ""
    append_row(PROOFS, [label, now_iso(), host, path, before["sha256"],
                        before["entries"], before["bytes"], "PASS",
                        "pre_post_metadata_equal;consistency_adapter_pass;source_retained",
                        consistency_before["fingerprint"],
                        json.dumps(consistency_before, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")),
                        committed_version])
    with phase("catalog_rebuild_post"):
        run([str(CATALOG)], capture_output=True, text=True)
    with phase("vault_sync_post"):
        run([str(SYNC)], capture_output=True, text=True)
    return {"asset_id": label, "snapshot": before,
            "consistency": consistency_before, "uploader_tail": out[-2000:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--path", required=True)
    ap.add_argument("--label")
    ap.add_argument("--description", default="Workspace Pager automatic cold snapshot")
    # Authority is workspace_pager_policy.json ("cold_days"); ws always passes it
    # explicitly.  This literal is only the manual-invocation fallback and must track
    # policy -- the retired 15-day value silently re-imposed the old age-driven schedule.
    ap.add_argument("--cold-days", type=float, default=3)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    host = canonical_host(args.host)
    path = validate_target(host, args.path)
    with phase("require_cold_page"):
        page = ({"age_days": None} if args.test_mode
                else require_cold_page(host, path, args.cold_days))
    with phase("assert_no_running_worker"):
        assert_no_running_worker(host, path)
    with phase("assert_no_open_handles"):
        assert_no_open_handles(host, path)
    with phase("consistency_before"):
        consistency_before = consistency(host, path)
    with phase("snapshot_before"):
        before = snapshot(host, path)
    result = {"verdict": "ARCHIVE_SHADOW_PASS", "host": host, "path": path,
              "asset_id": args.label or asset_label(host, path),
              "age_days": page.get("age_days"), "snapshot": before,
              "consistency": consistency_before,
              "source_retained": True, "deletion_implemented": False}
    _CTX.update({"host": host, "path": path, "label": result["asset_id"],
                 "size_bytes": before.get("bytes")})
    if args.execute:
        with LOCK.open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ArchiveRefused("REFUSE_WORKSPACE_ARCHIVER_BUSY") from exc
            result.update(execute_archive(host, path, result["asset_id"],
                                          args.description, before, consistency_before))
            result["verdict"] = "ARCHIVE_COPY_PASS"
    flush_phase_timing(host, path, result["asset_id"], result["verdict"],
                       before.get("bytes"))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArchiveRefused as exc:
        flush_phase_timing(_CTX.get("host"), _CTX.get("path"), _CTX.get("label"),
                           str(exc)[:120], _CTX.get("size_bytes"))
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
