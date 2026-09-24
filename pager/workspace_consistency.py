#!/usr/bin/env python3
"""Read-only consistency proof for cold workspace snapshots.

The checker never freezes or mutates an application.  Callers must first
prove that no worker or process has the target open.  This module then rejects
dirty/in-progress Git repositories, validates quiescent SQLite databases, and
refuses database formats for which no consistent snapshot adapter exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import quote


PROOF_VERSION = 1
SQLITE_MAGIC = b"SQLite format 3\x00"
UNSUPPORTED_SUFFIXES = {".duckdb", ".lmdb", ".mdbx"}
GIT_IN_PROGRESS = {
    "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG",
    "rebase-apply", "rebase-merge", "sequencer",
}


class ConsistencyRefused(RuntimeError):
    pass


def _run_git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True,
        stdin=subprocess.DEVNULL, timeout=120,
    )
    if proc.returncode:
        raise ConsistencyRefused(
            "REFUSE_GIT_INSPECTION repo=%s rc=%d detail=%s"
            % (repo, proc.returncode, proc.stderr[-1000:].strip())
        )
    return proc.stdout.strip()


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        if ".git" in dirs:
            dirs.remove(".git")
        for name in files:
            path = Path(base) / name
            if not path.is_symlink():
                yield path


def _target_has_tracked_paths(repo: Path, target: Path) -> bool:
    # target != repo is guaranteed by the only caller (the containing-repo
    # branch below only reaches here when containing != target.resolve()),
    # so rel is always a real subpath, never ".".
    rel = target.resolve().relative_to(repo)
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--", str(rel)],
        text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    if proc.returncode:
        raise ConsistencyRefused(
            "REFUSE_GIT_INSPECTION repo=%s rc=%d detail=%s"
            % (repo, proc.returncode, proc.stderr[-1000:].strip())
        )
    return bool(proc.stdout)


def _git_roots(target: Path) -> list[Path]:
    start = target if target.is_dir() else target.parent
    roots: set[Path] = set()
    proc = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
    )
    if proc.returncode == 0:
        containing = Path(proc.stdout.strip()).resolve()
        if containing != target.resolve():
            # target is a subdirectory, not the repo's own toplevel. That is
            # only safe to archive/delete without a whole-repo consistency
            # proof when *nothing under target* is git-tracked -- i.e. the
            # entire subtree is untracked (gitignored or not), so touching it
            # can never disturb HEAD or the working tree relative to any
            # commit. Real <date> case: 示例项目/示例产线/产物/*
            # and .agent-agent-f/research/* are archive candidates that are
            # fully .gitignore'd data trees inside source-controlled repos;
            # refusing them here blocked the entire cold-archive backlog on a
            # false-positive git risk. If even one tracked path exists
            # underneath, we still cannot prove partial-tree consistency and
            # must keep refusing.
            if _target_has_tracked_paths(containing, target):
                raise ConsistencyRefused(
                    f"REFUSE_GIT_PARTIAL_ROOT target={target} repo={containing}"
                )
        else:
            roots.add(containing)
    if target.is_dir():
        for base, dirs, files in os.walk(target, topdown=True, followlinks=False):
            dirs.sort()
            files.sort()
            if ".git" in dirs or ".git" in files:
                roots.add(Path(base).resolve())
            if ".git" in dirs:
                dirs.remove(".git")
    return sorted(roots, key=str)


def _inspect_git(target: Path) -> list[dict]:
    proofs = []
    for repo in _git_roots(target):
        if _run_git(repo, "rev-parse", "--is-bare-repository") == "true":
            raise ConsistencyRefused(f"REFUSE_UNSUPPORTED_GIT_BARE repo={repo}")
        git_dir_raw = _run_git(repo, "rev-parse", "--git-dir")
        git_dir = Path(git_dir_raw)
        if not git_dir.is_absolute():
            git_dir = (repo / git_dir).resolve()
        busy = sorted(
            name for name in GIT_IN_PROGRESS if (git_dir / name).exists()
        )
        locks = sorted(str(p.relative_to(git_dir)) for p in git_dir.glob("*.lock"))
        if busy or locks:
            raise ConsistencyRefused(
                f"REFUSE_GIT_IN_PROGRESS repo={repo} markers={busy + locks}"
            )
        dirty = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
        if dirty:
            sample = dirty.splitlines()[:10]
            raise ConsistencyRefused(f"REFUSE_GIT_DIRTY repo={repo} sample={sample}")
        proofs.append({
            "root": str(repo),
            "head": _run_git(repo, "rev-parse", "HEAD"),
            "status": "clean",
        })
    return proofs


def _unsupported_database_markers(target: Path) -> list[str]:
    markers = []
    roots: dict[Path, set[str]] = {}
    for path in _walk(target):
        name = path.name
        if name == "PG_VERSION":
            markers.append("postgresql:%s" % path)
        if path.suffix.casefold() in UNSUPPORTED_SUFFIXES:
            markers.append("unsupported-db:%s" % path)
        if name in {"data.mdb", "lock.mdb"}:
            markers.append("lmdb:%s" % path)
        if name in {"dump.rdb", "appendonly.aof"}:
            markers.append("redis:%s" % path)
        if name == "CURRENT" or name.startswith("MANIFEST-") or name.startswith("OPTIONS-"):
            roots.setdefault(path.parent, set()).add(name)
    for root, names in roots.items():
        if "CURRENT" in names and any(x.startswith("MANIFEST-") for x in names):
            markers.append("leveldb-or-rocksdb:%s" % root)
    return sorted(set(markers))


def _sqlite_files(target: Path) -> list[Path]:
    found = []
    for path in _walk(target):
        try:
            if path.stat().st_size < len(SQLITE_MAGIC):
                continue
            with path.open("rb", buffering=0) as handle:
                if handle.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC:
                    found.append(path)
        except OSError as exc:
            raise ConsistencyRefused(
                f"REFUSE_DATABASE_SIGNATURE_READ path={path} error={exc}"
            ) from exc
    return sorted(found, key=str)


def _inspect_sqlite(target: Path) -> list[dict]:
    proofs = []
    for path in _sqlite_files(target):
        # <date>: 原判据是「sidecar 文件存在即拒」。实测它把一个**已经死掉**的
        # pnpm 缓存库永久挡在归档之外:index.db-wal 是 0 字节、无任何进程持有,
        # 却让 3.6GB 的 vendor 页连续被拒 172 次 —— 而淘汰器正因为缺合格候选饿死。
        # 判据收窄到「真有未落盘数据」:
        #   -wal / -journal 字节数 > 0  → 确实有未 checkpoint 帧/回滚日志,照旧拒。
        #   -wal / -journal 为 0 字节    → sqlite 规范下等价于已 checkpoint,放行。
        #   -shm                        → 纯共享内存索引,从不含持久数据(官方文档明示
        #                                 可安全删除);它单独存在不再构成拒绝理由,
        #                                 真有数据的场景必然伴随非空 -wal,已被上面拦住。
        # 注意:stat 失败一律当「有数据」拒绝,不允许读不到就放行。
        sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")]
        present = [str(p) for p in sidecars if p.exists()]
        dirty = []
        for side in sidecars:
            if side.name.endswith("-shm") or not side.exists():
                continue
            try:
                if side.stat().st_size > 0:
                    dirty.append(str(side))
            except OSError as exc:
                raise ConsistencyRefused(
                    f"REFUSE_SQLITE_SIDECAR_STAT db={path} sidecar={side} error={exc}"
                ) from exc
        if dirty:
            raise ConsistencyRefused(
                f"REFUSE_SQLITE_UNCHECKPOINTED db={path} sidecars={dirty}"
            )
        uri = "file:%s?mode=ro" % quote(str(path.resolve()), safe="/")
        try:
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                conn.execute("PRAGMA query_only=ON")
                verdicts = [str(r[0]) for r in conn.execute("PRAGMA quick_check")]
                page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
                schema_version = int(conn.execute("PRAGMA schema_version").fetchone()[0])
        except sqlite3.Error as exc:
            raise ConsistencyRefused(
                f"REFUSE_SQLITE_QUICK_CHECK db={path} error={exc}"
            ) from exc
        if verdicts != ["ok"]:
            raise ConsistencyRefused(
                f"REFUSE_SQLITE_QUICK_CHECK db={path} verdicts={verdicts[:10]}"
            )
        proofs.append({
            "path": str(path), "quick_check": "ok",
            # 证据要如实:放行的原因是「没有未落盘数据」,不是「文件不存在」。
            # 空 sidecar 逐个列出来,将来复盘时能看见当时到底放行了什么。
            "sidecars": "absent" if not present else "empty:%s" % ",".join(
                Path(p).name for p in present),
            "page_count": page_count, "schema_version": schema_version,
        })
    return proofs


def inspect_workspace(raw_path: str | os.PathLike[str]) -> dict:
    target = Path(raw_path)
    if not target.exists() or target.is_symlink():
        raise ConsistencyRefused(f"REFUSE_CONSISTENCY_TARGET path={target}")
    unsupported = _unsupported_database_markers(target)
    if unsupported:
        raise ConsistencyRefused(
            f"REFUSE_UNSUPPORTED_DATABASE_SNAPSHOT markers={unsupported[:20]}"
        )
    body = {
        "version": PROOF_VERSION,
        "target": str(target.resolve()),
        "git": _inspect_git(target),
        "sqlite": _inspect_sqlite(target),
        "unsupported_database_markers": [],
        "verdict": "PASS",
    }
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    body["fingerprint"] = hashlib.sha256(canonical.encode()).hexdigest()
    return body


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_workspace(args.path), ensure_ascii=False, sort_keys=True))
    except ConsistencyRefused as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
