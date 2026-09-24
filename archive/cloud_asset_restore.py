#!/usr/bin/env python3
"""Fail-closed restore from opaque Baidu blobs, with optional auto-download."""
import argparse
import csv
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from baidu_client_download import DOWNLOAD_ROOT, DownloadRefused, download_cloud_file
from vault_v2_versions import VersionRefused, VersionStore

WS = Path(__file__).resolve().parent
KEY = (Path(os.environ["COLDSTORE_GPG_KEYFILE"]).expanduser()
       if os.environ.get("COLDSTORE_GPG_KEYFILE")
       else WS / ".secrets" / "gpg.passphrase")  # never committed; see config/archive.env.example
CLOUD_BASE = os.environ.get("COLDSTORE_CLOUD_BASE", "/ColdArchive")
DOWNLOAD_METRICS = WS / "cloud_asset_download_metrics.tsv"
REMOTE = os.environ.get("COLDSTORE_REMOTE", "user@host-b")
# (incident note) Approved remote staging roots, isolated mount first: a
# verification restore must never fill the managed pool it is trying to relieve.
REMOTE_OUTPUT_ROOTS = ("/data/baidu-vault-restore", "/home/user/.cache/baidu-vault-restore")
REMOTE_OUTPUT_ROOT = REMOTE_OUTPUT_ROOTS[-1]  # legacy managed-pool root, kept for callers/tests


def remote_output_root_for(path):
    for root in REMOTE_OUTPUT_ROOTS:
        if str(path).startswith(root + "/"):
            return root
    return None


def record_download_metric(asset_id, part, result, path=DOWNLOAD_METRICS):
    """Append one verified download metric with an advisory cross-process lock."""
    columns = [
        "asset_id", "part", "started_at", "finished_at", "verdict", "bytes",
        "download_elapsed_s", "download_MBps", "download_MiBps", "task_id",
    ]
    task = result.get("task") or {}
    row = [
        asset_id, str(part), result.get("started_at") or "", result.get("finished_at") or "",
        result["verdict"], str(result["bytes"]), str(result.get("download_elapsed_s", "")),
        "" if result.get("download_MBps") is None else str(result["download_MBps"]),
        "" if result.get("download_MiBps") is None else str(result["download_MiBps"]),
        str(task.get("task_id", "")),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8", newline="") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.seek(0, os.SEEK_END)
        if f.tell() == 0:
            csv.writer(f, delimiter="\t", lineterminator="\n").writerow(["# " + columns[0], *columns[1:]])
        csv.writer(f, delimiter="\t", lineterminator="\n").writerow(row)
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def catalog(asset):
    for line in (WS / "cloud_asset_catalog.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r["asset_id"] == asset:
            return r
    raise SystemExit(f"UNKNOWN_ASSET {asset}")


def ledger(asset):
    store = VersionStore(WS)
    if store.heads_path.exists():
        try:
            return store.head_rows(asset)
        except VersionRefused as exc:
            raise SystemExit(str(exc)) from exc
    # Append-only ledger rows may revoke/supersede an earlier part.  The audit
    # tool's authoritative rule is latest row per (root, part), not "all rows
    # that were ever CLOUD_CONFIRMED".
    latest = {}
    with (WS / "vault_v2_ledger.tsv").open(encoding="utf-8") as f:
        for r in csv.reader(f, delimiter="\t"):
            if len(r) == 12:
                latest[(r[1], r[3])] = r
    out = [r for r in latest.values() if r[2] == asset and r[11] == "CLOUD_CONFIRMED"]
    out.sort(key=lambda r: int(r[3]))
    if out:
        parts = [int(r[3]) for r in out]
        if parts != list(range(1, len(parts) + 1)):
            raise SystemExit(f"REFUSE_NONCONTIGUOUS_PARTS asset={asset} parts={parts[:20]}")
    return out


def copy_verified(stream, sink, expected_size, expected_sha256):
    """Copy one plaintext stream while proving its ledger size and digest.

    Bytes reach only the private tar extraction staging directory.  A mismatch
    therefore invalidates the whole staging tree; it can never be published as
    the final restored asset.
    """
    h = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
        sink.write(block)
        h.update(block)
        size += len(block)
    digest = h.hexdigest()
    if size != int(expected_size) or digest != expected_sha256:
        raise SystemExit(
            f"REFUSE_BAD_PLAINTEXT expected_bytes={expected_size} got_bytes={size} "
            f"expected_sha256={expected_sha256} got_sha256={digest}"
        )
    return size, digest


def decrypt_part_into_tar(blob, row, tar_stdin):
    """Decrypt and verify one ledger part without materializing plaintext."""
    proc = subprocess.Popen(
        ["/usr/local/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
         "--passphrase-file", str(KEY), "--decrypt", str(blob)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    try:
        size, digest = copy_verified(proc.stdout, tar_stdin, int(row[4]), row[5])
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    finally:
        proc.stdout.close()
    stderr = proc.stderr.read().decode("utf-8", errors="replace")[-2000:]
    proc.stderr.close()
    if proc.wait() != 0:
        raise SystemExit(f"REFUSE_GPG_FAILED part={row[3]} detail={stderr}")
    return size, digest


def validate_remote_output(raw):
    path = os.path.normpath(str(raw))
    root = remote_output_root_for(path)
    if root is None or path == root or ".." in Path(path).parts:
        raise SystemExit(f"REFUSE_REMOTE_OUTPUT_PATH {raw}")
    return path


RESTORE_LOCK_DIR = Path.home() / ".coldstore" / "state" / "restore-locks"
# Headroom the host keeps after the restore fully lands.  A machine at literal
# zero free bytes cannot create temp files, so every agent/tool on it dies --
# not just the restore.  This margin is what keeps the host recoverable.
DISK_SAFETY_MARGIN = 2 * 1024 ** 3
# A staging tree touched more recently than this is assumed live and never swept.
STAGING_SWEEP_QUIET_SECONDS = 600


def _safe_component(name):
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


def _free_bytes(path):
    """Free bytes on the filesystem that will actually hold ``path``."""
    p = Path(path).resolve()
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free


def acquire_asset_lock(asset_id):
    """Serialise restores per asset; refuse rather than queue.

    <date> incident: five sibling render tasks each asked the page gate to
    fault in the same 19.4GB engine.  ``mkdtemp`` gives every attempt its own
    random suffix, so nothing collided and nothing deduped -- eight concurrent
    restores of one asset were in flight.  The only pre-existing agent-b,
    ``REFUSE_OUTPUT_EXISTS``, checks the *published* path and therefore never
    fires while every attempt is still failing.
    """
    RESTORE_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    handle = (RESTORE_LOCK_DIR / f"{_safe_component(asset_id)}.lock").open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise SystemExit(f"REFUSE_RESTORE_ALREADY_RUNNING asset={asset_id}")
    return handle


def owner_marker(output, staging_name):
    """Sidecar recording which process owns a staging tree.

    Deliberately kept *outside* the staging directory: the tree is published by
    ``os.replace`` straight onto the restored asset path, so anything written
    inside it would end up polluting the restored asset.
    """
    return Path(output) / f".restore-owner-{staging_name}.json"


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def create_staging(output, asset_id):
    """Create a staging tree and record its owner in the same breath.

    These two steps must never agent-f apart: a staging tree without a live owner
    marker is indistinguishable from a corpse, and the fallback rule (directory
    mtime) is too weak to protect a long-running restore.
    """
    tmp_root = Path(tempfile.mkdtemp(prefix=f"restore-{asset_id}-", dir=output))
    owner_marker(output, tmp_root.name).write_text(json.dumps({
        "pid": os.getpid(), "asset_id": asset_id, "started_at": time.time(),
    }, sort_keys=True) + "\n", encoding="utf-8")
    return tmp_root


def sweep_orphan_stagings(asset_id, output):
    """Delete leftover staging trees for this asset.

    Only sound while holding the per-asset lock: no other restore of this asset
    can exist, so every ``restore-<asset>-*`` tree still on disk is the corpse
    of a failed run.  The failure path deliberately prints
    ``RESTORE_STAGING_RETAINED`` and keeps the tree, but nothing ever collected
    them -- 50GB of corpses from one asset filled the Mac to zero bytes.
    """
    removed = []
    cutoff = time.time() - STAGING_SWEEP_QUIET_SECONDS
    for path in sorted(Path(output).glob(f"restore-{asset_id}-*")):
        if not path.is_dir():
            continue
        marker = owner_marker(output, path.name)
        try:
            owner = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            owner = None
        if owner is None:
            # Written by a pre-marker build of this tool.  Directory mtime is a
            # weak liveness signal -- tar updates the *sub*directories it writes
            # into, not the staging root -- so this branch can only ever be a
            # conservative fallback, never the primary rule.
            try:
                if path.stat().st_mtime > cutoff:
                    print(f"ORPHAN_STAGING_SKIPPED_UNMARKED_RECENT name={path.name}")
                    continue
            except OSError:
                continue
        elif _pid_alive(int(owner.get("pid", -1))):
            # Cannot normally happen while we hold the per-asset lock; kept so a
            # stale lock can never turn into deletion of a live restore.
            print(f"ORPHAN_STAGING_SKIPPED_LIVE name={path.name} pid={owner.get('pid')}")
            continue
        shutil.rmtree(path, ignore_errors=True)
        marker.unlink(missing_ok=True)
        removed.append(path.name)
    return removed


def remote_disk_free(remote_base):
    """Inspect only the approved destination filesystem; never read payloads."""
    remote_base = validate_remote_output(remote_base)
    code = (
        "import json,os,pathlib,sys; "
        "p=pathlib.Path(sys.argv[1]).resolve(); "
        "root=pathlib.Path(sys.argv[2]).resolve(); "
        "assert root in p.parents, 'remote_output_escape'; "
        "p=next(x for x in (p,*p.parents) if x.exists()); "
        "s=os.statvfs(p); print(json.dumps({'free_bytes':s.f_bavail*s.f_frsize}))"
    )
    try:
        result = subprocess.run(
            ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", REMOTE,
             shlex.join(["python3", "-c", code, remote_base, remote_output_root_for(remote_base)])],
            text=True, capture_output=True, timeout=30, check=True,
        )
        free = json.loads(result.stdout)["free_bytes"]
        if type(free) is not int or free < 0:
            raise ValueError("invalid free_bytes")
        return free
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        raise SystemExit(f"REFUSE_REMOTE_DISK_PROBE_FAILED {type(exc).__name__}") from exc


def preflight_disk(parts, output, blob_dir, download, purge, remote_base,
                   remote_reserve_bytes=DISK_SAFETY_MARGIN):
    """Fail closed before the first byte if the restore cannot physically fit.

    Without this the restore starts a multi-GB stream on a volume with
    megabytes left, dies mid-tar, retains its staging tree, and makes the next
    attempt strictly more likely to fail -- a spiral that ends at zero bytes.
    """
    plain_total = sum(int(r[4]) for r in parts)
    if remote_base:
        # Remote extraction still consumes the entire plaintext. Previously
        # this path checked only the small Mac ciphertext staging directory.
        margin = max(DISK_SAFETY_MARGIN, int(remote_reserve_bytes))
        free = remote_disk_free(remote_base)
        detail = (f"need_bytes={plain_total} margin_bytes={margin} "
                  f"free_bytes={free} path={REMOTE}:{remote_base} for=remote-staging")
        if free < plain_total + margin:
            raise SystemExit(f"REFUSE_INSUFFICIENT_REMOTE_DISK {detail}")
        print(f"DISK_PREFLIGHT_PASS {detail}")
    missing_blob_total = 0
    if download:
        for r in parts:
            blob = Path(blob_dir) / f"{r[8]}.blob"
            if not (blob.is_file() and blob.stat().st_size == int(r[6])):
                missing_blob_total += int(r[6])
        if purge:
            # Only one blob is resident at a time when parts are purged.
            missing_blob_total = min(missing_blob_total,
                                     max((int(r[6]) for r in parts), default=0))
    checks = []
    if not remote_base:
        checks.append(("staging", Path(output), plain_total))
    if download:
        checks.append(("blobs", Path(blob_dir), missing_blob_total))
    merged = {}
    for label, path, need in checks:
        try:
            key = os.stat(_existing_ancestor(path)).st_dev
        except OSError:
            key = str(path)
        slot = merged.setdefault(key, {"labels": [], "need": 0, "path": path})
        slot["labels"].append(label)
        slot["need"] += need
    for slot in merged.values():
        need = slot["need"] + DISK_SAFETY_MARGIN
        free = _free_bytes(slot["path"])
        detail = (f"need_bytes={slot['need']} margin_bytes={DISK_SAFETY_MARGIN} "
                  f"free_bytes={free} path={slot['path']} for={'+'.join(slot['labels'])}")
        if free < need:
            raise SystemExit(f"REFUSE_INSUFFICIENT_DISK {detail}")
        print(f"DISK_PREFLIGHT_PASS {detail}")


def _existing_ancestor(path):
    p = Path(path).resolve()
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("asset_id")
    ap.add_argument("--blob-dir", type=Path, help="directory containing blobs downloaded by BaiduNetdisk")
    ap.add_argument("--output", type=Path, default=Path("/tmp/baidu-vault-restore"))
    ap.add_argument("--download", action="store_true", help="download exact blobs through logged-in Mac client")
    ap.add_argument("--download-dir", type=Path, help="Baidu sandbox staging directory (implies --download)")
    ap.add_argument("--download-timeout", type=float, default=1800)
    ap.add_argument("--remote-output",
                    help="stream extraction to an approved hostb directory")
    ap.add_argument("--purge-downloaded-parts", action="store_true",
                    help="remove each verified local download after decryption")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--preflight-only", action="store_true",
                    help="verify cloud proof and real disk capacity without downloading or creating files")
    ap.add_argument("--remote-reserve-bytes", type=int, default=DISK_SAFETY_MARGIN)
    args = ap.parse_args()
    if args.blob_dir and (args.download or args.download_dir):
        raise SystemExit("REFUSE_BLOB_DIR_WITH_AUTO_DOWNLOAD")
    if args.download_dir:
        args.download = True
    if args.purge_downloaded_parts and not args.download:
        raise SystemExit("REFUSE_PURGE_WITHOUT_DOWNLOAD")
    if args.remote_output and args.blob_dir:
        raise SystemExit("REFUSE_REMOTE_OUTPUT_WITH_BLOB_DIR")
    meta = catalog(args.asset_id)
    parts = ledger(args.asset_id)
    if meta["cloud_state"] != "confirmed" or not parts:
        raise SystemExit("REFUSE_NOT_CLOUD_CONFIRMED")
    if args.preflight_only:
        remote_base = validate_remote_output(args.remote_output) if args.remote_output else None
        blob_dir = args.blob_dir or args.download_dir or (
            DOWNLOAD_ROOT / "cloud-asset-restore" / _safe_component(args.asset_id))
        preflight_disk(parts, args.output, blob_dir, args.download,
                       args.purge_downloaded_parts, remote_base, args.remote_reserve_bytes)
        print(f"RESTORE_PREFLIGHT_PASS asset={args.asset_id} parts={len(parts)}")
        return
    print(f"ASSET {args.asset_id} state={meta['local_state']} original={meta['original_path']}")
    for r in parts:
        print(f"NEED {CLOUD_BASE}/{r[9]} sha256={r[7]} bytes={r[6]}")
    if args.plan or (args.blob_dir is None and not args.download):
        print("PLAN_ONLY rerun with --download, or provide --blob-dir DIR")
        return
    if not KEY.is_file() or KEY.stat().st_mode & 0o077:
        raise SystemExit("REFUSE_KEY_MISSING_OR_PERMISSIONS")
    # Held for the whole run; released when the process exits.  Must be taken
    # before any staging tree is created so the sweep below is provably safe.
    lock_handle = acquire_asset_lock(args.asset_id)
    if not args.remote_output:
        args.output.mkdir(parents=True, exist_ok=True)
    blob_dir = args.blob_dir
    if args.download:
        safe_asset = _safe_component(args.asset_id)
        blob_dir = args.download_dir or (DOWNLOAD_ROOT / "cloud-asset-restore" / safe_asset)
        blob_dir.mkdir(parents=True, exist_ok=True)
    assert blob_dir is not None
    remote_base = validate_remote_output(args.remote_output) if args.remote_output else None
    if not remote_base:
        swept = sweep_orphan_stagings(args.asset_id, args.output)
        if swept:
            print(f"ORPHAN_STAGING_SWEPT count={len(swept)} names={','.join(swept)}")
    preflight_disk(parts, args.output, blob_dir, args.download,
                   args.purge_downloaded_parts, remote_base, args.remote_reserve_bytes)
    if remote_base:
        final = f"{remote_base.rstrip('/')}/{args.asset_id}"
        tmp_root = f"{remote_base.rstrip('/')}/.restore-{args.asset_id}-{os.getpid()}"
        remote_prepare = (
            f"set -e; mkdir -p -- {shlex.quote(remote_base)}; "
            f"test ! -e {shlex.quote(final)}; test ! -e {shlex.quote(tmp_root)}; "
            f"mkdir -p -- {shlex.quote(tmp_root)}; "
            f"exec /usr/bin/tar -xf - -C {shlex.quote(tmp_root)}"
        )
    else:
        final = args.output / args.asset_id
        if final.exists():
            raise SystemExit(f"REFUSE_OUTPUT_EXISTS {final}")
        tmp_root = create_staging(args.output, args.asset_id)
    tar = None
    try:
        tar_command = (["ssh", REMOTE, remote_prepare] if remote_base else
                       ["/usr/bin/tar", "-xf", "-", "-C", str(tmp_root)])
        tar = subprocess.Popen(tar_command, stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        assert tar.stdin is not None
        for r in parts:
            blob = blob_dir / f"{r[8]}.blob"
            if args.download:
                try:
                    result = download_cloud_file(
                        f"{CLOUD_BASE}/{r[9]}", blob_dir,
                        expected_size=int(r[6]), expected_sha256=r[7],
                        timeout=args.download_timeout,
                    )
                except DownloadRefused as exc:
                    raise SystemExit(str(exc)) from exc
                record_download_metric(args.asset_id, r[3], result)
                print(
                    f"{result['verdict']} part={r[3]} bytes={result['bytes']} "
                    f"download_elapsed_s={result['download_elapsed_s']} "
                    f"download_MBps={result['download_MBps']} download_MiBps={result['download_MiBps']}"
                )
            if not blob.is_file() or blob.stat().st_size != int(r[6]) or sha(blob) != r[7]:
                raise SystemExit(f"REFUSE_BAD_BLOB part={r[3]} path={blob}")
            size, digest = decrypt_part_into_tar(blob, r, tar.stdin)
            print(f"PLAINTEXT_STREAM_PASS part={r[3]} bytes={size} sha256={digest}")
            if args.purge_downloaded_parts:
                blob.unlink(missing_ok=True)
        tar.stdin.close()
        tar_stderr = tar.stderr.read().decode("utf-8", errors="replace")[-2000:]
        if tar.wait() != 0:
            raise SystemExit(f"REFUSE_TAR_FAILED detail={tar_stderr}")
        tar = None
        if remote_base:
            publish = subprocess.run([
                "ssh", "-n", REMOTE,
                f"set -e; test ! -e {shlex.quote(final)}; "
                f"mv -- {shlex.quote(tmp_root)} {shlex.quote(final)}",
            ], text=True, capture_output=True)
            if publish.returncode:
                raise SystemExit(f"REFUSE_REMOTE_PUBLISH_FAILED {publish.stderr[-1000:]}")
            print(f"RESTORE_PASS asset={args.asset_id} output={REMOTE}:{final}")
        else:
            staging_name = tmp_root.name
            os.replace(tmp_root, final)
            owner_marker(args.output, staging_name).unlink(missing_ok=True)
            print(f"RESTORE_PASS asset={args.asset_id} output={final}")
    except BaseException:
        if tar is not None:
            try:
                if tar.stdin is not None and not tar.stdin.closed:
                    tar.stdin.close()
            except BrokenPipeError:
                pass
            if tar.poll() is None:
                tar.terminate()
            tar.wait()
        print(f"RESTORE_STAGING_RETAINED {REMOTE + ':' if remote_base else ''}{tmp_root}")
        raise


if __name__ == "__main__":
    main()
