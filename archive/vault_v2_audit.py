#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

WS = Path(os.environ.get("COLDSTORE_ARCHIVE_WS", "~/.coldstore/archive")).expanduser()
LEDGER = WS / 'vault_v2_ledger.tsv'
REPORT = WS / 'vault_v2_audit_latest.json'
NETDISK_HOME = Path.home() / "Library/Containers/com.baidu.netdisk/Data"
def _netdisk_account_db(name):
    """Desktop client keeps one hashed account directory; discover it instead of pinning an account id."""
    hits = sorted((NETDISK_HOME / "Library/Application Support/com.baidu.netdisk").glob("*/" + name))
    return hits[0] if hits else NETDISK_HOME / "Library/Application Support/com.baidu.netdisk/UNKNOWN" / name
DB = _netdisk_account_db('filecache.db')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--strict', action='store_true')
    args = ap.parse_args()
    expected = {}
    latest = {}
    if LEDGER.exists():
        for line in LEDGER.read_text(encoding='utf-8').splitlines():
            c = line.split('\t')
            if len(c) == 12:
                latest[(c[1], c[3])] = c
        for c in latest.values():
            if c[11] == 'CLOUD_CONFIRMED':
                expected[f'{c[8]}.blob'] = {
                    'root': c[1], 'label': c[2], 'part': int(c[3]),
                    'plain_size': int(c[4]), 'plain_sha256': c[5],
                    'encrypted_size': int(c[6]), 'encrypted_sha256': c[7],
                    'blob_id': c[8], 'cloud_relative_path': c[9],
                }
    with sqlite3.connect(DB) as conn:
        rows = conn.execute(
            "select server_filename,file_size,fid,parent_path from file_meta where parent_path like '%/ColdArchive/v2/%' and server_filename like '%.blob'"
        ).fetchall()
    actual = {r[0]: {'size': r[1], 'fid': r[2], 'parent_path': r[3]} for r in rows}
    missing = [v for k, v in expected.items() if k not in actual]
    mismatched = [
        {**v, 'actual_size': actual[k]['size']}
        for k, v in expected.items() if k in actual and actual[k]['size'] != v['encrypted_size']
    ]
    unexpected = [
        {'server_filename': k, **v} for k, v in actual.items() if k not in expected
    ]
    report = {
        'created_at': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'),
        'basis': 'BaiduNetdisk filecache.db; refresh client folder before authoritative audit',
        'expected_blobs': len(expected), 'cached_cloud_blobs': len(actual),
        'missing_count': len(missing), 'mismatched_count': len(mismatched),
        'unexpected_count': len(unexpected), 'missing': missing,
        'mismatched': mismatched, 'unexpected': unexpected,
        'verdict': 'PASS' if not missing and not mismatched and not unexpected else 'FAIL',
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    REPORT.chmod(0o600)
    print(json.dumps({k: report[k] for k in ['expected_blobs','cached_cloud_blobs','missing_count','mismatched_count','unexpected_count','verdict']}, ensure_ascii=False))
    if args.strict and report['verdict'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
