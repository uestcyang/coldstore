#!/usr/bin/env python3
import json
import os
import errno
import hashlib
import fcntl
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

WS = Path(os.environ.get("COLDSTORE_ARCHIVE_WS", "~/.coldstore/archive")).expanduser()
KEY = (Path(os.environ["COLDSTORE_GPG_KEYFILE"]).expanduser()
       if os.environ.get("COLDSTORE_GPG_KEYFILE")
       else WS / ".secrets" / "gpg.passphrase")  # never committed; see config/archive.env.example
ICLOUD = Path(os.environ.get('COLDSTORE_ICLOUD_DIR', '~/Library/Mobile Documents/com~apple~CloudDocs/coldstore-recovery')).expanduser()
REMOTE = os.environ.get("COLDSTORE_REMOTE", "user@host-b")
REMOTE_DIR = os.environ.get('COLDSTORE_REMOTE_ARCHIVE_WS', '/home/user/.coldstore/archive')
FILES = [
    WS / 'vault_v2_ledger.tsv',
    WS / 'vault_v2_roots.tsv',
    WS / 'vault_v2_sources.tsv',
    WS / 'vault_v2_heads.json',
    WS / 'vault_v2_pending.json',
    WS / 'vault_v2_versions.jsonl',
    WS / 'vault_v2_blob_gc.tsv',
    WS / 'VAULT_V2_RESTORE.md',
    WS / 'cloud_asset_catalog.jsonl',
    WS / 'cloud_asset_manifest.tsv',
    WS / 'cloud_asset_semantic_anchors.tsv',
    WS / 'cloud_asset_restore_tests.tsv',
    WS / 'cloud_asset_download_metrics.tsv',
    WS / 'cloud_asset_three_copy.tsv',
    WS / 'workspace_snapshot_proofs.tsv',
    WS / 'workspace_semantics.jsonl',
    WS / 'cloud_asset_catalog.py',
    WS / 'cloud_asset_find.py',
    WS / 'cloud_asset_restore.py',
    WS / 'vault_v2_sync.py',
    WS / 'vault_v2_stream.py',
    WS / 'baidu_client_download.py',
    WS / 'cloud_asset_delete_gate.py',
    WS / 'cloud_asset_evict_once.py',
    WS / 'logical_vault_v3_evict.py',
    WS / 'workspace_archive.py',
    WS / 'vault_v2_manifest.py',
    WS / 'vault_v2_versions.py',
    WS / 'baidu_client_delete.py',
    WS / 'cloud_blob_gc.py',
    WS / 'workspace_pool_migrate_remote.py',
    WS / 'workspace_pool_migration_refresh.py',
    WS / 'workspace_pool_migration_manifest.json',
    WS / 'run_vault_v2_manifest_hostb.sh',
    WS / 'run_vault_v2_manifest_after_primary.sh',
    WS / 'queue_hostb_manifest_expansion_20260829.tsv',
    WS / 'logical_vault_v3.sqlite3',
    WS / 'logical_vault_v3_events.jsonl',
    WS / 'logical_vault_v3_restore_metrics.tsv',
    WS / 'logical_vault_v3.py',
    WS / 'LOGICAL_VAULT_V3.md',
    WS / 'FUNCTION_V2_MIGRATION_HOLD',
]


def run(args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL)


def sync_files(files, destination):
    """Checksum-selected, atomic per-file transfer; never delete destination files.

    A files-from list avoids ARG_MAX at thousands of manifests. Using -c rather
    than only mtime/size also detects a changed frozen snapshot with reused times.
    Final SHA/three-copy checks below remain authoritative.
    """
    if not files:
        return
    parents = {p.parent for p in files}
    if len(parents) != 1 or any(p.is_symlink() or not p.is_file() for p in files):
        raise RuntimeError('REFUSE_SYNC_SOURCE_SET')
    parent = next(iter(parents))
    with tempfile.NamedTemporaryFile(prefix='vault-sync-files-', suffix='.list') as listing:
        listing.write(b''.join(os.fsencode(p.name) + b'\0' for p in files))
        listing.flush()
        run([shutil.which('rsync') or '/usr/bin/rsync', '-rltc', '--from0',
             '--files-from=' + listing.name, '--', str(parent) + '/', destination])


def _read_sha256(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


# (incident note) Hydrate-on-demand for evicted iCloud copies.
# macOS evicts CloudDocs files to dataless placeholders under disk pressure.
# stat() still reports the full size, so the eviction is invisible until a
# read raises EDEADLK (errno 11) / ENODATA. On <date> all 2398 `verified-*.gpg`
# copies were evicted when the root disk hit 100%, and this function -- called
# for every one of them on every sync -- made vault_v2_sync.py fail outright.
# That is the worst possible coupling: the sync is needed most precisely when
# the disk is full, i.e. exactly when eviction has happened. Fail-closed: if a
# file cannot be materialised after the bounded retries, the error propagates.
_HYDRATE_ERRNOS = {errno.EDEADLK, errno.ENODATA, errno.ENOENT}


def sha256_file(path: Path, *, attempts: int = 4):
    for attempt in range(attempts):
        try:
            return _read_sha256(path)
        except OSError as exc:
            if exc.errno not in _HYDRATE_ERRNOS or attempt == attempts - 1:
                raise
            subprocess.run(['/usr/bin/brctl', 'download', str(path)],
                           capture_output=True, timeout=120)
            time.sleep(0.5 * (2 ** attempt))
    raise AssertionError('unreachable')


def ensure_icloud_key():
    key_copy = ICLOUD / 'vault-v2-master.key'
    expected = sha256_file(KEY)
    if key_copy.exists():
        # iCloud File Provider can transiently return EDEADLK when a hydrated
        # file is repeatedly opened while metadata files are being replaced.
        # The key was SHA-verified at provisioning; per-part sync must never
        # reopen or overwrite it.  A size change still fails closed.
        if key_copy.stat().st_size != KEY.stat().st_size:
            raise RuntimeError('iCloud master key size mismatch; refusing overwrite')
        return key_copy
    key_tmp = ICLOUD / f'.vault-v2-master.key.{os.getpid()}.tmp'
    shutil.copy2(KEY, key_tmp)
    os.chmod(key_tmp, 0o600)
    if sha256_file(key_tmp) != expected:
        raise RuntimeError('iCloud temporary key SHA-256 mismatch')
    os.replace(key_tmp, key_copy)
    return key_copy


# Incident note: every archived page called this sync twice and each call
# re-encrypted *all* 115 metadata/manifest/version files into iCloud.  Manifests
# are immutable once written, so that work is pure waste and grows O(n) with the
# vault — the measured cost was ~110s of fixed overhead per archived page.
# The sidecar below skips a re-encryption only when the *source* file is byte
# identical to what was last encrypted.  It fails open: a missing/corrupt
# sidecar, a missing target, or any read error falls back to re-encrypting.
ICLOUD_SYNC_STATE = WS / '.icloud_sync_state.json'


def load_icloud_sync_state():
    try:
        data = json.loads(ICLOUD_SYNC_STATE.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_icloud_sync_state(state):
    try:
        tmp = ICLOUD_SYNC_STATE.with_name(ICLOUD_SYNC_STATE.name + f'.{os.getpid()}.tmp')
        tmp.write_text(json.dumps(state, sort_keys=True), encoding='utf-8')
        os.replace(tmp, ICLOUD_SYNC_STATE)
    except Exception:
        pass


def should_skip_icloud(src: Path, state, icloud_dir: Path):
    """True only when the ciphertext in iCloud already covers this exact source.

    Every uncertain case must return False so the file is re-encrypted:
    unreadable source, unknown/mismatched fingerprint, or missing ciphertext.
    """
    fingerprint = source_fingerprint(src)
    if fingerprint is None:
        return False, None
    if state.get(src.name) != fingerprint:
        return False, fingerprint
    if not (icloud_dir / f'{src.name}.gpg').is_file():
        return False, fingerprint
    return True, fingerprint


def source_fingerprint(src: Path):
    """Identity of the plaintext we last encrypted.  None forces re-encryption."""
    try:
        st = src.stat()
        return f'{st.st_size}:{st.st_mtime_ns}'
    except OSError:
        return None


def encrypt_to_icloud(src: Path):
    local_tmp = WS / f'.{src.name}.{os.getpid()}.gpg.tmp'
    target = ICLOUD / f'{src.name}.gpg'
    target_tmp = ICLOUD / f'.{src.name}.{os.getpid()}.gpg.tmp'
    run([
        '/usr/local/bin/gpg', '--batch', '--yes', '--pinentry-mode', 'loopback',
        '--passphrase-file', str(KEY), '--symmetric', '--cipher-algo', 'AES256',
        '--compress-algo', 'none', '--output', str(local_tmp), str(src),
    ])
    shutil.copy2(local_tmp, target_tmp)
    os.replace(target_tmp, target)
    local_tmp.unlink(missing_ok=True)


def snapshot_sqlite(src: Path, destination: Path):
    """Create a transactionally consistent copy of a live SQLite control plane."""
    source = sqlite3.connect(f'file:{src}?mode=ro', uri=True, timeout=60)
    target = sqlite3.connect(str(destination))
    try:
        source.backup(target)
        verdict = target.execute('PRAGMA quick_check').fetchone()[0]
        if verdict != 'ok':
            raise RuntimeError(f'SQLite snapshot quick_check failed: {verdict}')
        target.commit()
    finally:
        target.close()
        source.close()


def snapshot_file(source, destination):
    before = source.stat()
    shutil.copy2(source, destination)
    after = source.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        destination.unlink(missing_ok=True)
        raise RuntimeError('metadata changed during snapshot: ' + source.name)


def _sync_locked():
    if not KEY.is_file() or KEY.stat().st_mode & 0o077:
        raise SystemExit('master key missing or permissions not 0600')
    ICLOUD.mkdir(parents=True, exist_ok=True)
    catalog = WS / 'cloud_asset_catalog.jsonl'
    catalog_inputs = [
        WS / 'vault_v2_sources.tsv', WS / 'vault_v2_roots.tsv',
        WS / 'queue_mac.tsv', WS / 'queue_hostb_cold_verified_20260829.tsv',
        WS / 'queue_hostb_manifest_expansion_20260829.tsv',
    ]
    newest_input = max((p.stat().st_mtime for p in catalog_inputs if p.exists()), default=0)
    if not catalog.exists() or catalog.stat().st_mtime < newest_input:
        run([str(WS / 'cloud_asset_catalog.py')])
    key_copy = ensure_icloud_key()
    metadata = [p for p in FILES if p.is_file()]
    manifest_files = sorted((WS / 'manifests').glob('*.gz')) if (WS / 'manifests').is_dir() else []
    version_files = sorted((WS / 'vault_v2_version_parts').glob('*.json')) if (WS / 'vault_v2_version_parts').is_dir() else []
    with tempfile.TemporaryDirectory(prefix='vault-state-sync-') as temporary:
        snapshot_dir = Path(temporary)
        transport_metadata = []
        for src in metadata:
            if src.name == 'logical_vault_v3.sqlite3':
                snapshot = snapshot_dir / src.name
                snapshot_sqlite(src, snapshot)
                transport_metadata.append(snapshot)
            else:
                snapshot = snapshot_dir / src.name
                snapshot_file(src, snapshot)
                transport_metadata.append(snapshot)
        existing = transport_metadata + manifest_files + version_files
        icloud_state = load_icloud_sync_state()
        encrypted = skipped = 0
        for src in existing:
            skip, fingerprint = should_skip_icloud(src, icloud_state, ICLOUD)
            if src.name == 'cloud_asset_catalog.jsonl':
                skip = False
            if skip:
                skipped += 1
                continue
            encrypt_to_icloud(src)
            if fingerprint is not None:
                icloud_state[src.name] = fingerprint
            encrypted += 1
        save_icloud_sync_state(icloud_state)
        run(['ssh', '-n', REMOTE, f'mkdir -p {REMOTE_DIR}/manifests {REMOTE_DIR}/version_parts && chmod 700 {REMOTE_DIR} {REMOTE_DIR}/manifests {REMOTE_DIR}/version_parts'])
        if transport_metadata:
            sync_files(transport_metadata, f'{REMOTE}:{REMOTE_DIR}/')
        if manifest_files:
            sync_files(manifest_files, f'{REMOTE}:{REMOTE_DIR}/manifests/')
        if version_files:
            sync_files(version_files, f'{REMOTE}:{REMOTE_DIR}/version_parts/')
        # Never apply a file mode through a wildcard: manifests/ is part of that
        # expansion and chmod 600 removes its search bit, breaking the next part.
        run([
            'ssh', '-n', REMOTE,
            f"find {REMOTE_DIR} -maxdepth 1 -type f -exec chmod 600 {{}} + && "
            f"find {REMOTE_DIR}/manifests -maxdepth 1 -type f -exec chmod 600 {{}} + && "
            f"find {REMOTE_DIR}/version_parts -maxdepth 1 -type f -exec chmod 600 {{}} + && "
            f"chmod 700 {REMOTE_DIR} {REMOTE_DIR}/manifests {REMOTE_DIR}/version_parts",
        ])
        frozen_catalog = snapshot_dir / 'cloud_asset_catalog.jsonl'
        expected = sha256_file(frozen_catalog)
        remote_result = subprocess.run(
            ['ssh', '-n', REMOTE, 'sha256sum', f'{REMOTE_DIR}/cloud_asset_catalog.jsonl'],
            capture_output=True, text=True, timeout=30, check=True,
        )
        if remote_result.stdout.split()[0] != expected:
            raise RuntimeError('frozen catalog remote hash mismatch')
        local_stage = WS / f'.last_synced_catalog.{os.getpid()}.tmp'
        shutil.copy2(frozen_catalog, local_stage)
        os.replace(local_stage, WS / '.last_synced_catalog.jsonl')
        receipt = {'catalog_sha256': expected,
                   'catalog_cipher_sha256': sha256_file(ICLOUD / 'cloud_asset_catalog.jsonl.gpg'),
                   'catalog_bytes': frozen_catalog.stat().st_size}
        receipt['verified_manifests'] = {path.name: {'sha256': sha256_file(path),
            'cipher_sha256': sha256_file(ICLOUD / (path.name + '.gpg'))}
            for path in manifest_files if path.name.startswith('verified-')}
        receipt_stage = WS / f'.metadata_sync_receipt.{os.getpid()}.tmp'
        receipt_stage.write_text(json.dumps(receipt, sort_keys=True) + '\n')
        os.replace(receipt_stage, WS / '.metadata_sync_receipt.json')
        print(f'STATE_SYNC_OK files={len(existing)} icloud_encrypted={encrypted} '
              f'icloud_skipped={skipped} icloud_key={key_copy}')


def main():
    with (WS / '.metadata_sync.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _sync_locked()


if __name__ == '__main__':
    main()
