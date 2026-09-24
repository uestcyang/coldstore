#!/usr/bin/env python3
import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from vault_v2_versions import VersionStore

CHUNK = 1_000_000_000
BUF = 8 * 1024 * 1024
WS = Path(os.environ.get("COLDSTORE_ARCHIVE_WS", "~/.coldstore/archive")).expanduser()
NETDISK_HOME = Path.home() / "Library/Containers/com.baidu.netdisk/Data"
def _netdisk_account_db(name):
    """Desktop client keeps one hashed account directory; discover it instead of pinning an account id."""
    hits = sorted((NETDISK_HOME / "Library/Application Support/com.baidu.netdisk").glob("*/" + name))
    return hits[0] if hits else NETDISK_HOME / "Library/Application Support/com.baidu.netdisk/UNKNOWN" / name
STAGE = NETDISK_HOME / 'Documents' / os.environ.get('COLDSTORE_STAGE_DIR', 'ColdArchive')
INCOMING = NETDISK_HOME / 'tmp' / 'ColdArchiveIncoming'
DB = _netdisk_account_db('transmission.db')
KEY = (Path(os.environ["COLDSTORE_GPG_KEYFILE"]).expanduser()
       if os.environ.get("COLDSTORE_GPG_KEYFILE")
       else WS / ".secrets" / "gpg.passphrase")  # never committed; see config/archive.env.example
LEDGER = WS / 'vault_v2_ledger.tsv'
SYNC = WS / 'vault_v2_sync.py'
CLOUD_TIMEOUT_SECONDS = 21600
REANNOUNCE_AFTER_SECONDS = 300
REANNOUNCE_INTERVAL_SECONDS = 300
REANNOUNCE_MAX = 3
STREAM_LOCK = WS / '.vault_v2_stream.lock'
WRITER_LOCKS = (STREAM_LOCK, WS / '.workspace_archive.lock', WS / '.logical_vault_v3.lock')
WRITER_PATTERNS = ('vault_v2_stream.py', 'logical_vault_v3.py upload',
                   'workspace_archive.py', 'stream_shards.py')
_PYTHON_PROC = re.compile(r'^\d+\s+(\S*python[\d.]*)\s', re.IGNORECASE)
_STREAM_LOCK_HANDLE = None


def pager_priority_reason(flag, now=None):
    """Read the advisory writer lease. Expiry never bypasses actual flock locks."""
    try:
        text = Path(flag).read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
    except OSError as exc:
        return 'flag_unreadable:' + type(exc).__name__
    try:
        record = json.loads(text)
        if isinstance(record, dict):
            expires = record.get('expires_at')
            if expires is None and isinstance(record.get('ts'), (int, float)):
                expires = record['ts'] + 1800
            if expires is not None and float(expires) <= (time.time() if now is None else now):
                return None
    except (ValueError, TypeError):
        pass  # malformed/legacy flags remain fail-closed, not silently discarded
    return text.strip()[:300] or 'pager_priority'


def vault_writer_busy(exclude=(), locks=None):
    """First live Baidu-staging writer, or None.

    The staging folder is single-writer by contract (<date>: three files
    staged together ran 11.7x slower and killed the client's folder watcher).
    Lock files are probed first (deterministic: a writer holds its flock for its
    whole run); ``pgrep`` is only a fallback and is filtered to real python
    processes -- <date> a bare ``pgrep -f`` matched an agent's zsh wrapper
    whose command *text* merely mentioned the script name and stalled the drain.
    ``exclude`` lists the caller's own lock(s).
    """
    excluded = {str(p) for p in exclude}
    for lock in (WRITER_LOCKS if locks is None else locks):
        lock = Path(lock)
        if str(lock) in excluded or not lock.exists():
            continue
        try:
            with lock.open('a+') as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return f'lock-held {lock.name}'
                fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            continue
    me = os.getpid()
    for pattern in WRITER_PATTERNS:
        proc = subprocess.run(['pgrep', '-fal', pattern], text=True, capture_output=True)
        for line in proc.stdout.splitlines():
            head = line.split(None, 1)
            if not head or not head[0].isdigit() or int(head[0]) in (me, os.getppid()):
                continue
            if _PYTHON_PROC.match(line):
                return line[:300]
    return None


def acquire_stream_lock():
    """One vault_v2_stream per machine; refuse (not queue) a second one."""
    global _STREAM_LOCK_HANDLE
    handle = STREAM_LOCK.open('a+')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise SystemExit('REFUSE_VAULT_STREAM_BUSY another vault_v2_stream holds ' + str(STREAM_LOCK))
    _STREAM_LOCK_HANDLE = handle


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')


def rows():
    if not LEDGER.exists():
        return []
    out = []
    with LEDGER.open('r', encoding='utf-8', errors='strict') as f:
        for line in f:
            cols = line.rstrip('\n').split('\t')
            if len(cols) == 12:
                out.append(cols)
    return out


def confirmed_row(root, part, plain_size, plain_sha):
    for cols in reversed(rows()):
        if cols[1] == root and cols[3] == str(part) and cols[4] == str(plain_size) and cols[5] == plain_sha and cols[11] == 'CLOUD_CONFIRMED':
            return cols
    return None


def confirmed(root, part, plain_size, plain_sha):
    return confirmed_row(root, part, plain_size, plain_sha) is not None


def backup_status(path):
    conn = sqlite3.connect(DB)
    try:
        return conn.execute(
            'select file_size, coalesce(reserved1,-1) from backup_file '
            'where local_filename=? order by rowid desc limit 1',
            (str(path),),
        ).fetchone()
    finally:
        conn.close()


def reannounce_stage_file(path, size, expected_sha):
    """Re-emit one missed file-create event without deleting any bytes."""
    if not path.is_file() or path.stat().st_size != size:
        raise RuntimeError(f'reannounce source agent-f: {path}')
    before_sha = sha256_file(path)
    if before_sha != expected_sha:
        raise RuntimeError(f'reannounce hash agent-f before move: {path}')
    before_inode = path.stat().st_ino
    hold = INCOMING / f'.reannounce-{path.name}'
    if hold.exists():
        raise RuntimeError(f'reannounce hold already exists: {hold}')
    os.replace(path, hold)
    try:
        os.replace(hold, path)
    finally:
        if not path.exists() and hold.exists():
            os.replace(hold, path)
    if (not path.is_file() or path.stat().st_size != size
            or path.stat().st_ino != before_inode
            or sha256_file(path) != expected_sha):
        raise RuntimeError(f'reannounce post-move agent-f: {path}')
    print(
        f'BACKUP_EVENT_REANNOUNCED path={path} bytes={size} '
        f'sha256={expected_sha} inode={before_inode}', flush=True)


def wait_cloud(path, size, expected_sha):
    started = time.time()
    deadline = started + CLOUD_TIMEOUT_SECONDS
    next_reannounce = started + REANNOUNCE_AFTER_SECONDS
    reannounced = 0
    while time.time() < deadline:
        row = backup_status(path)
        if row and row[0] == size and row[1] == 2:
            return
        current = time.time()
        # The Baidu client occasionally misses a create/rename FSEvent after a
        # long sequential backup.  Only a completely absent transfer-DB row is
        # eligible for re-announcement.  A known pending/uploading row is never
        # touched.  Atomic moves preserve the encrypted bytes and inode.
        if (row is None and reannounced < REANNOUNCE_MAX
                and current >= next_reannounce):
            reannounce_stage_file(path, size, expected_sha)
            reannounced += 1
            next_reannounce = current + REANNOUNCE_INTERVAL_SECONDS
        time.sleep(5)
    raise RuntimeError(f'backup timeout: {path}')


def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(BUF), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--label', required=True)
    ap.add_argument('--root', required=True)
    args = ap.parse_args()
    if not KEY.is_file() or KEY.stat().st_mode & 0o077:
        raise SystemExit('master key missing or permissions not 0600')
    key_bytes = KEY.read_bytes()
    acquire_stream_lock()
    INCOMING.mkdir(parents=True, exist_ok=True)
    STAGE.mkdir(parents=True, exist_ok=True)
    LEDGER.touch(mode=0o600, exist_ok=True)
    root_tag = hmac.new(key_bytes, args.root.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    part = 0
    total = 0
    session_rows = []
    stream = sys.stdin.buffer
    while True:
        part += 1
        plain = INCOMING / f'v2-{root_tag}-{part:04d}.plain'
        h_plain = hashlib.sha256()
        n = 0
        with plain.open('wb') as out:
            while n < CHUNK:
                block = stream.read(min(BUF, CHUNK - n))
                if not block:
                    break
                out.write(block)
                h_plain.update(block)
                n += len(block)
        if n == 0:
            plain.unlink(missing_ok=True)
            break
        total += n
        plain_sha = h_plain.hexdigest()
        prior = confirmed_row(args.root, part, n, plain_sha)
        if prior:
            session_rows.append(prior)
            plain.unlink()
            print(f'SKIP_CONFIRMED label={args.label} part={part} bytes={n}', flush=True)
            continue
        msg = f'vault-v2\0{args.root}\0{part}\0{plain_sha}'.encode('utf-8')
        blob_id = hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()
        encrypted_tmp = INCOMING / f'{blob_id}.blob'
        subprocess.run([
            '/usr/local/bin/gpg', '--batch', '--yes', '--pinentry-mode', 'loopback',
            '--passphrase-file', str(KEY), '--symmetric', '--cipher-algo', 'AES256',
            '--compress-algo', 'none', '--output', str(encrypted_tmp), str(plain),
        ], check=True, stdin=subprocess.DEVNULL)
        enc_size = encrypted_tmp.stat().st_size
        enc_sha = sha256_file(encrypted_tmp)
        rel = Path('v2') / blob_id[:2] / f'{blob_id}.blob'
        dest = STAGE / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(encrypted_tmp, dest)
        wait_cloud(dest, enc_size, enc_sha)
        ledger_row = [
            now(), args.root, args.label, str(part), str(n), plain_sha,
            str(enc_size), enc_sha, blob_id, str(rel), 'AES256-GPG', 'CLOUD_CONFIRMED',
        ]
        with LEDGER.open('a', encoding='utf-8') as f:
            f.write('\t'.join(ledger_row) + '\n')
            f.flush()
            os.fsync(f.fileno())
        session_rows.append(ledger_row)
        # (incident note) Reclaim the staged ciphertext BEFORE the state sync.
        # The ledger row above is fsynced and already records CLOUD_CONFIRMED --
        # wait_cloud() verified the uploaded copy -- so the local blob is pure
        # redundancy from here on. While these unlinks sat behind a check=True
        # sync, a single vault_v2_sync.py failure stranded a ~1GB blob per part
        # forever. That is what happened from <date>: sync hit ENOSPC, every
        # subsequent part leaked its blob, 172 blobs / 48GB accumulated, the Mac
        # root disk hit 100%, and the full disk then guaranteed the next sync
        # would fail too -- a self-reinforcing spiral. Freeing disk must never
        # depend on an operation that fails when the disk is full.
        dest.unlink(missing_ok=True)
        plain.unlink(missing_ok=True)
        subprocess.run([str(SYNC)], check=True, stdin=subprocess.DEVNULL)
        print(f'CLOUD_CONFIRMED blob={blob_id} part={part} plain_bytes={n} encrypted_bytes={enc_size}', flush=True)
    receipt = VersionStore(WS).stage(args.label, args.root, session_rows)
    subprocess.run([str(SYNC)], check=True, stdin=subprocess.DEVNULL)
    print(
        f'VAULT_STREAM_DONE label={args.label} parts={part-1} plaintext_bytes={total} '
        f'version_id={receipt["version_id"]} head_switched=false', flush=True,
    )


if __name__ == '__main__':
    main()
