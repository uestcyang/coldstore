#!/usr/bin/env python3
"""Deterministic BaiduNetdisk desktop-client download adapter.

This module does not scrape cookies or call undocumented public HTTP APIs.  It
uses the already logged-in Mac desktop client through the client's existing
Chrome DevTools endpoint and its own native downloader.  Cloud metadata is
resolved from the client's local cache and every completed blob is checked by
size and, when supplied, SHA-256.

The adapter is deliberately narrow:

* only the existing client at 127.0.0.1:9223 is accepted;
* downloads may only land below BaiduNetdisk's sandbox Downloads directory;
* an existing mismatching file is never overwritten;
* ambiguous/missing cloud metadata and non-zero native return codes fail shut.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import time
import urllib.request
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


APP_SUPPORT = Path.home() / "Library/Containers/com.baidu.netdisk/Data/Library/Application Support/com.baidu.netdisk"
DOWNLOAD_ROOT = Path.home() / "Library/Containers/com.baidu.netdisk/Data/Downloads"
DEVTOOLS_JSON = "http://127.0.0.1:9223/json"
# (incident note) The desktop client re-creates its account directory for a
# few seconds around a native resume/restart; bounded wait before refusing.
DB_DISCOVERY_WAIT_S = 120.0
DB_DISCOVERY_POLL_S = 1.0


class DownloadRefused(RuntimeError):
    """Raised when a fail-closed precondition is not satisfied."""


@dataclass(frozen=True)
class CloudFile:
    fid: int
    parent_path: str
    filename: str
    size: int
    md5: str

    @property
    def cloud_path(self) -> str:
        return self.parent_path.rstrip("/") + "/" + self.filename


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _single_account_db(name: str, *, wait_s: float | None = None,
                       clock=time.monotonic, sleep=time.sleep) -> Path:
    """Exactly one account database, or refuse.

    <date>: three multi-GB restores (dataset-a, dataset-b,
    live-service) died with ``REFUSE_TRANSMISSION_DB_COUNT count=0``
    right after a native 1252007 resume -- the desktop client briefly re-creates
    its account directory and the whole asset restore was thrown away for that
    window.  count==0 now waits up to DB_DISCOVERY_WAIT_S; count>1 stays an
    immediate refusal (an ambiguous account cannot be resolved by waiting).
    Fail-closed after the window.
    """
    wait_s = DB_DISCOVERY_WAIT_S if wait_s is None else float(wait_s)
    deadline = clock() + max(0.0, wait_s)
    announced = False
    while True:
        try:
            # glob suppresses scandir errors (including EMFILE) and used to report
            # a vanished database when a leaking process exhausted its descriptors.
            with os.scandir(APP_SUPPORT) as entries:
                matches = sorted(Path(entry.path) / name for entry in entries
                                 if entry.is_dir(follow_symlinks=False)
                                 and (Path(entry.path) / name).is_file())
        except OSError as exc:
            raise DownloadRefused(
                f"REFUSE_LOCAL_DB_DISCOVERY db={name} errno={exc.errno}"
            ) from exc
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1 or clock() >= deadline:
            raise DownloadRefused(
                f"REFUSE_{name.upper().replace('.', '_')}_COUNT count={len(matches)}"
                + (f" waited_s={int(wait_s)}" if not matches and wait_s > 0 else "")
            )
        if not announced:
            print(f"DB_DISCOVERY_WAIT db={name} count=0 wait_s={int(wait_s)}", flush=True)
            announced = True
        sleep(DB_DISCOVERY_POLL_S)


def _verified_complete_output(output: Path, meta: "CloudFile", expected_sha256: str | None) -> str | None:
    """sha256 of a fully landed output, or None.

    <date>: the desktop client flagged task <task-id> status=5/error=1252007
    with complete_size == file_size and hostb-dataset-c was refused eight
    times although the exact bytes were on disk.  The ciphertext SHA-256 is the
    authority for "downloaded", not the client's flag; without an expected
    digest nothing is accepted.
    """
    if not expected_sha256:
        return None
    try:
        st = output.stat()
    except OSError:
        return None
    if not output.is_file() or st.st_size != meta.size:
        return None
    digest = sha256(output)
    return digest if digest == expected_sha256 else None


def _pass_result(meta: "CloudFile", output: Path, digest: str | None, task: dict[str, Any] | None,
                 started_at: datetime, started_mono: float, retries: int, *,
                 native_status_ignored: bool = False) -> dict[str, Any]:
    finished_at = datetime.now().astimezone()
    elapsed = max(time.monotonic() - started_mono, 1e-9)
    result = {
        "verdict": "DOWNLOAD_PASS", "output": str(output), "bytes": meta.size,
        "sha256": digest, "cloud": asdict(meta), "task": task,
        "started_at": started_at.isoformat(timespec="milliseconds"),
        "finished_at": finished_at.isoformat(timespec="milliseconds"),
        "download_elapsed_s": round(elapsed, 3),
        "download_MBps": round(meta.size / elapsed / 1_000_000, 3),
        "download_MiBps": round(meta.size / elapsed / 1_048_576, 3),
        "native_retries": retries,
    }
    if native_status_ignored:
        result["native_status_ignored"] = True
    return result


def lookup_cloud_file(cloud_path: str, db_path: Path | None = None) -> CloudFile:
    p = PurePosixPath(cloud_path)
    if not p.is_absolute() or p.name in ("", ".", ".."):
        raise DownloadRefused(f"REFUSE_BAD_CLOUD_PATH {cloud_path!r}")
    parent = str(p.parent).rstrip("/") + "/"
    db_path = db_path or _single_account_db("filecache.db")
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        rows = conn.execute(
            "SELECT fid,parent_path,server_filename,file_size,md5 "
            "FROM file_meta WHERE parent_path=? AND server_filename=? AND isdir=0",
            (parent, p.name),
        ).fetchall()
    if len(rows) != 1:
        raise DownloadRefused(
            f"REFUSE_CLOUD_METADATA_COUNT count={len(rows)} path={cloud_path}"
        )
    row = rows[0]
    return CloudFile(
        fid=int(row[0]), parent_path=str(row[1]), filename=str(row[2]),
        size=int(row[3]), md5=str(row[4] or ""),
    )


def _safe_output_dir(output_dir: Path) -> Path:
    root = DOWNLOAD_ROOT.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = output_dir.resolve()
    if resolved != root and root not in resolved.parents:
        raise DownloadRefused(
            f"REFUSE_OUTPUT_OUTSIDE_BAIDU_SANDBOX output={resolved} root={root}"
        )
    # Keep the caller's sandbox-visible spelling.  On this Mac the container
    # Downloads directory resolves to ~/Downloads, but the native MAS client
    # must receive the container path that its sandbox already owns.
    return output_dir.absolute()


def _devtools_page(endpoint: str = DEVTOOLS_JSON) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(endpoint, timeout=3) as response:
            pages = json.load(response)
    except Exception as exc:
        raise DownloadRefused(f"REFUSE_BAIDU_DEVTOOLS_UNREACHABLE {exc}") from exc
    candidates = [
        p for p in pages
        if p.get("type") == "page"
        and "BaiduNetdisk.app/Contents/Resources/core.asar/index.html" in p.get("url", "")
    ]
    preferred = [p for p in candidates if "category=all" in p.get("url", "")]
    chosen = (preferred or candidates)
    if not chosen or not chosen[0].get("webSocketDebuggerUrl"):
        raise DownloadRefused("REFUSE_BAIDU_MAIN_PAGE_NOT_FOUND")
    return chosen[0]


def _native_call(expression: str, endpoint: str = DEVTOOLS_JSON) -> int:
    try:
        import websocket  # type: ignore
    except ImportError as exc:
        raise DownloadRefused("REFUSE_WEBSOCKET_CLIENT_MISSING") from exc

    page = _devtools_page(endpoint)
    try:
        ws = websocket.create_connection(
            page["webSocketDebuggerUrl"], timeout=5, suppress_origin=True
        )
        try:
            ws.send(json.dumps({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                },
            }))
            while True:
                response = json.loads(ws.recv())
                if response.get("id") == 1:
                    break
        finally:
            ws.close()
    except Exception as exc:
        raise DownloadRefused(f"REFUSE_BAIDU_CDP_CALL_FAILED {exc}") from exc

    try:
        value = response["result"]["result"]["value"]
    except (KeyError, TypeError) as exc:
        raise DownloadRefused(
            "REFUSE_BAIDU_CDP_BAD_RESPONSE " + json.dumps(response, ensure_ascii=False)
        ) from exc
    if value.get("error"):
        raise DownloadRefused(f"REFUSE_BAIDU_NATIVE_EXCEPTION {value['error']}")
    code = int(value.get("code", -1))
    if code != 0:
        raise DownloadRefused(f"REFUSE_BAIDU_NATIVE_CODE code={code}")
    return code


def _native_submit(meta: CloudFile, output_dir: Path, endpoint: str = DEVTOOLS_JSON) -> int:
    item = {
        "md5": meta.md5, "size": meta.size, "is_dir": 0,
        "server_path": meta.cloud_path, "local_path": str(output_dir),
    }
    return _native_call(
        "(()=>{try{return {code:require('@electron/remote').app.$downloader."
        "addDownloadTask(" + json.dumps([item], ensure_ascii=False)
        + ",'self',false,'0')}}catch(e){return {error:String(e)}}})()", endpoint,
    )


def _native_resume(meta: CloudFile, output: Path, failed: dict[str, Any],
                   db_path: Path | None = None, endpoint: str = DEVTOOLS_JSON) -> bool:
    """Resume only the exact failed download owned by this invocation.

    The desktop client's own partial file is retained.  Never enqueue all tasks
    or change login/network settings. Recheck task identity just before acting.
    """
    current = _task_status(meta, output, db_path)
    if not current or current.get("status") != 5 or not current.get("error_code"):
        return False  # It has already made progress; poll again.
    if (current.get("task_id") != failed.get("task_id")
            or current.get("local_path") != str(output)
            or current.get("file_size") != meta.size
            or int(current.get("task_id", 0)) <= 0):
        raise DownloadRefused("REFUSE_RESUME_TASK_OWNERSHIP_CHANGED")
    _native_call(
        "(()=>{try{return {code:require('@electron/remote').app.$downloader."
        "enqueueTask(" + json.dumps([str(current["task_id"])])
        + ",'0')}}catch(e){return {error:String(e)}}})()", endpoint,
    )
    return True


def _task_status(meta: CloudFile, output: Path, db_path: Path | None = None) -> dict[str, Any] | None:
    db_path = db_path or _single_account_db("transmission.db")
    # Connection.__exit__ only ends a transaction; it does not close the DB.
    # Long downloads poll here thousands of times. Close deterministically,
    # rather than depending on cyclic GC under the parent's workload.
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
        row = conn.execute(
            "SELECT task_id,status,error_code,complete_size,file_size,local_path "
            "FROM download_file WHERE server_path=? AND local_path=? "
            "ORDER BY add_time DESC LIMIT 1",
            (meta.cloud_path, str(output)),
        ).fetchone()
    if not row:
        return None
    return {
        "task_id": int(row[0]), "status": int(row[1]), "error_code": int(row[2]),
        "complete_size": int(row[3]), "file_size": int(row[4]), "local_path": str(row[5]),
    }


def cache_has_pending_downloads(directory: Path, db_path: Path | None = None) -> bool:
    """Read only: conservatively retain cache while native tasks can still write."""
    directory = directory.absolute()
    root = DOWNLOAD_ROOT.resolve()
    resolved = directory.resolve()
    if resolved == root or root not in resolved.parents or directory.is_symlink():
        raise DownloadRefused("REFUSE_CACHE_OUTSIDE_DOWNLOAD_ROOT")
    prefix = str(directory).rstrip('/') + '/'
    db_path = db_path or _single_account_db('transmission.db')
    with closing(sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)) as conn:
        row = conn.execute(
            'SELECT 1 FROM download_file WHERE substr(local_path,1,?)=? '
            'AND (status IS NULL OR status!=5) LIMIT 1',
            (len(prefix), prefix),
        ).fetchone()
    return row is not None


def download_cloud_file(
    cloud_path: str,
    output_dir: Path,
    *,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
    timeout: float = 1800,
    poll_interval: float = 1.0,
    filecache_db: Path | None = None,
    transmission_db: Path | None = None,
    endpoint: str = DEVTOOLS_JSON,
) -> dict[str, Any]:
    meta = lookup_cloud_file(cloud_path, filecache_db)
    if expected_size is not None and meta.size != expected_size:
        raise DownloadRefused(
            f"REFUSE_CLOUD_SIZE expected={expected_size} cached={meta.size} path={cloud_path}"
        )
    output_dir = _safe_output_dir(output_dir)
    output = output_dir / meta.filename
    if output.exists():
        if not output.is_file() or output.stat().st_size != meta.size:
            raise DownloadRefused(f"REFUSE_EXISTING_OUTPUT_MISMATCH path={output}")
        digest = sha256(output) if expected_sha256 else None
        if expected_sha256 and digest != expected_sha256:
            raise DownloadRefused(f"REFUSE_EXISTING_OUTPUT_BAD_SHA256 path={output}")
        return {
            "verdict": "DOWNLOAD_REUSED", "output": str(output), "bytes": meta.size,
            "sha256": digest, "cloud": asdict(meta), "task": _task_status(meta, output, transmission_db),
            "started_at": None, "finished_at": None,
            "download_elapsed_s": 0.0, "download_MBps": None, "download_MiBps": None,
        }

    started_at = datetime.now().astimezone()
    started_mono = time.monotonic()
    prior_task = _task_status(meta, output, transmission_db)
    prior_failed = prior_task if (prior_task and prior_task.get('status') == 5
                                  and prior_task.get('error_code')) else None
    _native_submit(meta, output_dir, endpoint)
    deadline = time.monotonic() + timeout
    submitted_mono = started_mono
    retries = 0
    stable_signature: tuple[int, int] | None = None
    stable_polls = 0
    last_task = None
    last_digest = None
    while time.monotonic() < deadline:
        last_task = _task_status(meta, output, transmission_db)
        if last_task and last_task["error_code"] and last_task["status"] == 5:
            # addDownloadTask returns before the native task database updates.
            # Do not mistake the previous failed row for this new submission.
            if (prior_failed and last_task == prior_failed
                    and time.monotonic() - submitted_mono < min(10.0, timeout)):
                time.sleep(poll_interval)
                continue
            # Observed desktop-client failure near the end of a blob. Its
            # undocumented numeric meaning is not assumed. At most three
            # native resumes, under the same total deadline, can recover a
            # transient failure without restarting the whole asset restore.
            if last_task["error_code"] == 1252007 and retries < 3:
                delay = (2.0, 5.0, 10.0)[retries]
                if time.monotonic() + delay < deadline:
                    time.sleep(delay)
                    resumed = _native_resume(meta, output, last_task, transmission_db, endpoint)
                    retries += 1
                    prior_failed = last_task if resumed else None
                    submitted_mono = time.monotonic()
                    print(f"DOWNLOAD_RESUME task={last_task['task_id']} retry={retries} "
                          f"resumed={str(resumed).lower()}", flush=True)
                    continue
            verified = _verified_complete_output(output, meta, expected_sha256)
            if verified is not None:
                print(f"DOWNLOAD_NATIVE_STATUS_IGNORED task={last_task['task_id']} "
                      f"error={last_task['error_code']} reason=output_complete_sha256_verified",
                      flush=True)
                return _pass_result(meta, output, verified, last_task, started_at, started_mono,
                                    retries, native_status_ignored=True)
            raise DownloadRefused(
                f"REFUSE_BAIDU_TASK_FAILED task={last_task['task_id']} "
                f"error={last_task['error_code']} retries={retries}"
            )
        if last_task and (not prior_failed or last_task != prior_failed):
            prior_failed = None
        try:
            st = output.stat()
        except FileNotFoundError:
            stable_signature = None
            stable_polls = 0
            time.sleep(poll_interval)
            continue
        if st.st_size > meta.size:
            raise DownloadRefused(
                f"REFUSE_DOWNLOADED_FILE_OVERSIZE expected={meta.size} actual={st.st_size}"
            )
        signature = (st.st_size, st.st_mtime_ns)
        if signature == stable_signature:
            stable_polls += 1
        else:
            stable_signature, stable_polls = signature, 0
        if st.st_size == meta.size and stable_polls >= 2:
            if expected_sha256:
                last_digest = sha256(output)
                if last_digest != expected_sha256:
                    stable_signature = None
                    stable_polls = 0
                    time.sleep(poll_interval)
                    continue
            return _pass_result(meta, output, last_digest, last_task, started_at, started_mono, retries)
        time.sleep(poll_interval)
    raise DownloadRefused(
        f"REFUSE_DOWNLOAD_TIMEOUT seconds={timeout} path={cloud_path} "
        f"task={json.dumps(last_task, ensure_ascii=False)}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Download one exact Baidu cloud object via desktop client")
    ap.add_argument("cloud_path")
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--expected-size", type=int)
    ap.add_argument("--expected-sha256")
    ap.add_argument("--timeout", type=float, default=1800)
    args = ap.parse_args()
    try:
        result = download_cloud_file(
            args.cloud_path, args.output_dir,
            expected_size=args.expected_size,
            expected_sha256=args.expected_sha256,
            timeout=args.timeout,
        )
    except DownloadRefused as exc:
        print(str(exc))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
