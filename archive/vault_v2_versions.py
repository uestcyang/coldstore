#!/usr/bin/env python3
"""Immutable vault-version receipts and atomic logical-asset heads.

The append-only upload ledger is transport evidence, not a restore index: a
second upload of the same root can otherwise expose a mixture of old and new
parts while it is still running.  This module freezes one completed stream into
an immutable receipt, then switches the logical asset head only after the root
ledger records ROOT_CLOUD_CONFIRMED.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

WS = Path(__file__).resolve().parent
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VersionRefused(RuntimeError):
    pass


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                       dir=path.parent)
    tmp = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise VersionRefused(f"REFUSE_VERSION_JSON_INVALID path={path}") from exc


def read_tsv(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return [row for row in csv.reader(handle, delimiter="\t") if len(row) == 12]
    except FileNotFoundError:
        return []


def identity_rows(rows):
    return [
        {
            "part": int(row[3]), "plaintext_bytes": int(row[4]),
            "plaintext_sha256": row[5], "encrypted_bytes": int(row[6]),
            "encrypted_sha256": row[7], "blob_id": row[8],
            "cloud_relative_path": row[9], "cipher": row[10],
        }
        for row in rows
    ]


def version_id_for_rows(rows):
    return hashlib.sha256(canonical_json(identity_rows(rows))).hexdigest()


class VersionStore:
    def __init__(self, root=WS):
        self.root = Path(root)
        self.ledger = self.root / "vault_v2_ledger.tsv"
        self.roots = self.root / "vault_v2_roots.tsv"
        self.parts_dir = self.root / "vault_v2_version_parts"
        self.heads_path = self.root / "vault_v2_heads.json"
        self.pending_path = self.root / "vault_v2_pending.json"
        self.events_path = self.root / "vault_v2_versions.jsonl"

    def heads_doc(self):
        doc = read_json(self.heads_path, {
            "schema_version": 1, "generation": 0, "heads": {},
        })
        if doc.get("schema_version") != 1 or not isinstance(doc.get("heads"), dict):
            raise VersionRefused("REFUSE_HEADS_SCHEMA")
        return doc

    def pending_doc(self):
        doc = read_json(self.pending_path, {
            "schema_version": 1, "generation": 0, "pending": {},
        })
        if doc.get("schema_version") != 1 or not isinstance(doc.get("pending"), dict):
            raise VersionRefused("REFUSE_PENDING_SCHEMA")
        return doc

    @staticmethod
    def pending_key(asset_id, root):
        return asset_id + "\0" + root

    @staticmethod
    def validate_rows(asset_id, root, rows):
        normalized = [[str(value) for value in row] for row in rows]
        if not normalized:
            raise VersionRefused("REFUSE_EMPTY_VERSION")
        for row in normalized:
            if len(row) != 12 or row[1] != root or row[2] != asset_id:
                raise VersionRefused("REFUSE_VERSION_ROW_IDENTITY")
            if row[11] != "CLOUD_CONFIRMED":
                raise VersionRefused("REFUSE_VERSION_PART_NOT_CLOUD_CONFIRMED")
            for index in (5, 7, 8):
                if SHA256_RE.fullmatch(row[index]) is None:
                    raise VersionRefused("REFUSE_VERSION_HASH_INVALID")
        normalized.sort(key=lambda row: int(row[3]))
        parts = [int(row[3]) for row in normalized]
        if parts != list(range(1, len(parts) + 1)):
            raise VersionRefused(f"REFUSE_VERSION_PARTS_NONCONTIGUOUS parts={parts[:20]}")
        if len(set(parts)) != len(parts):
            raise VersionRefused("REFUSE_VERSION_DUPLICATE_PART")
        return normalized

    def stage(self, asset_id, root, rows):
        rows = self.validate_rows(asset_id, root, rows)
        version_id = version_id_for_rows(rows)
        staged_at = now_iso()
        receipt = {
            "schema_version": 1,
            "asset_id": asset_id,
            "root": root,
            "version_id": version_id,
            "staged_at": staged_at,
            "part_count": len(rows),
            "plaintext_bytes": sum(int(row[4]) for row in rows),
            "encrypted_bytes": sum(int(row[6]) for row in rows),
            "parts": rows,
        }
        part_path = self.parts_dir / f"{version_id}.json"
        if part_path.exists():
            existing = read_json(part_path, None)
            if (existing.get("asset_id") != asset_id
                    or existing.get("root") != root
                    or existing.get("parts") != rows):
                raise VersionRefused("REFUSE_VERSION_ID_COLLISION")
        else:
            atomic_json(part_path, receipt)
        pending = self.pending_doc()
        pending["generation"] = int(pending.get("generation") or 0) + 1
        pending["pending"][self.pending_key(asset_id, root)] = {
            key: receipt[key] for key in (
                "asset_id", "root", "version_id", "staged_at", "part_count",
                "plaintext_bytes", "encrypted_bytes",
            )
        }
        atomic_json(self.pending_path, pending)
        return receipt

    def latest_ledger_rows(self, asset_id, root):
        latest = {}
        for row in read_tsv(self.ledger):
            if row[1] == root and row[2] == asset_id:
                latest[int(row[3])] = row
        return self.validate_rows(asset_id, root, list(latest.values()))

    def root_confirmation(self, asset_id, root):
        found = None
        try:
            with self.roots.open(encoding="utf-8") as handle:
                for row in csv.reader(handle, delimiter="\t"):
                    if len(row) >= 6 and row[1] == root and row[2] == asset_id:
                        found = row
        except FileNotFoundError:
            pass
        if not found or found[5] != "ROOT_CLOUD_CONFIRMED":
            raise VersionRefused("REFUSE_ROOT_NOT_CLOUD_CONFIRMED")
        return found

    def append_event(self, event):
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("ab") as handle:
            handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def commit(self, asset_id, root, version_id=None, *, bootstrap=False):
        pending = self.pending_doc()
        key = self.pending_key(asset_id, root)
        staged = pending["pending"].get(key)
        if not staged:
            raise VersionRefused("REFUSE_VERSION_NOT_STAGED")
        if version_id and staged["version_id"] != version_id:
            raise VersionRefused("REFUSE_PENDING_VERSION_MISMATCH")
        confirmation = self.root_confirmation(asset_id, root)
        if not bootstrap:
            try:
                confirmed_at = datetime.fromisoformat(confirmation[0])
                staged_at = datetime.fromisoformat(staged["staged_at"])
            except ValueError as exc:
                raise VersionRefused("REFUSE_VERSION_TIMESTAMP_INVALID") from exc
            if confirmed_at < staged_at:
                raise VersionRefused("REFUSE_ROOT_CONFIRMATION_PREDATES_VERSION")
        receipt = read_json(
            self.parts_dir / f"{staged['version_id']}.json", None
        )
        if not receipt or receipt.get("version_id") != staged["version_id"]:
            raise VersionRefused("REFUSE_VERSION_RECEIPT_MISSING")
        rows = self.validate_rows(asset_id, root, receipt.get("parts") or [])
        if version_id_for_rows(rows) != staged["version_id"]:
            raise VersionRefused("REFUSE_VERSION_RECEIPT_HASH_MISMATCH")

        heads = self.heads_doc()
        old = heads["heads"].get(asset_id)
        committed_at = now_iso()
        new_head = {
            key: staged[key] for key in (
                "asset_id", "root", "version_id", "part_count",
                "plaintext_bytes", "encrypted_bytes",
            )
        }
        new_head["committed_at"] = committed_at
        new_head["previous_version_id"] = old.get("version_id") if old else None
        if old and old.get("version_id") == new_head["version_id"]:
            # Idempotent recovery: the head is already right; just clear stale pending.
            pending["pending"].pop(key, None)
            pending["generation"] = int(pending.get("generation") or 0) + 1
            atomic_json(self.pending_path, pending)
            return new_head

        heads["generation"] = int(heads.get("generation") or 0) + 1
        heads["heads"][asset_id] = new_head
        atomic_json(self.heads_path, heads)
        self.append_event({
            "at": committed_at, "event": "HEAD_COMMITTED",
            "asset_id": asset_id, "root": root,
            "version_id": new_head["version_id"],
            "previous_version_id": new_head["previous_version_id"],
        })
        if old:
            self.append_event({
                "at": committed_at, "event": "VERSION_SUPERSEDED",
                "asset_id": asset_id, "root": old.get("root"),
                "version_id": old.get("version_id"),
                "superseded_by": new_head["version_id"],
            })
        pending["pending"].pop(key, None)
        pending["generation"] = int(pending.get("generation") or 0) + 1
        atomic_json(self.pending_path, pending)
        return new_head

    def head(self, asset_id):
        return self.heads_doc()["heads"].get(asset_id)

    def head_rows(self, asset_id):
        head = self.head(asset_id)
        if not head:
            raise VersionRefused(f"REFUSE_ASSET_WITHOUT_CURRENT_HEAD asset={asset_id}")
        receipt = read_json(self.parts_dir / f"{head['version_id']}.json", None)
        if not receipt:
            raise VersionRefused("REFUSE_CURRENT_VERSION_RECEIPT_MISSING")
        rows = self.validate_rows(asset_id, head["root"], receipt.get("parts") or [])
        if version_id_for_rows(rows) != head["version_id"]:
            raise VersionRefused("REFUSE_CURRENT_VERSION_RECEIPT_HASH_MISMATCH")
        return rows

    def bootstrap_confirmed(self):
        latest_roots = {}
        try:
            with self.roots.open(encoding="utf-8") as handle:
                for row in csv.reader(handle, delimiter="\t"):
                    if len(row) >= 6:
                        latest_roots[row[2]] = row
        except FileNotFoundError:
            return {"imported": [], "skipped": []}
        imported, skipped = [], []
        for asset_id, root_row in sorted(latest_roots.items()):
            if root_row[5] != "ROOT_CLOUD_CONFIRMED":
                skipped.append({"asset_id": asset_id, "reason": root_row[5]})
                continue
            if self.head(asset_id):
                continue
            try:
                rows = self.latest_ledger_rows(asset_id, root_row[1])
                receipt = self.stage(asset_id, root_row[1], rows)
                self.commit(asset_id, root_row[1], receipt["version_id"], bootstrap=True)
                imported.append(asset_id)
            except VersionRefused as exc:
                skipped.append({"asset_id": asset_id, "reason": str(exc)})
        return {"imported": imported, "skipped": skipped}

    def status(self):
        heads = self.heads_doc()["heads"]
        pending = self.pending_doc()["pending"]
        return {
            "heads": len(heads), "pending": len(pending),
            "version_receipts": len(list(self.parts_dir.glob("*.json")))
            if self.parts_dir.is_dir() else 0,
        }

    def gc_candidates(self):
        """Return encrypted blobs owned only by explicitly superseded versions."""
        superseded = set()
        try:
            for line in self.events_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("event") == "VERSION_SUPERSEDED":
                    superseded.add(str(event.get("version_id") or ""))
        except FileNotFoundError:
            return []
        heads = {
            str(row.get("version_id")) for row in self.heads_doc()["heads"].values()
        }
        pending = {
            str(row.get("version_id")) for row in self.pending_doc()["pending"].values()
        }
        protected_versions = heads | pending
        receipts = {}
        if self.parts_dir.is_dir():
            for path in self.parts_dir.glob("*.json"):
                receipt = read_json(path, None)
                if receipt and receipt.get("version_id") == path.stem:
                    receipts[path.stem] = receipt
        protected_blobs = {
            row[8]
            for version_id in protected_versions
            for row in (receipts.get(version_id) or {}).get("parts", [])
        }
        candidates = {}
        for version_id in sorted(superseded - protected_versions):
            receipt = receipts.get(version_id)
            if not receipt:
                raise VersionRefused(
                    f"REFUSE_SUPERSEDED_RECEIPT_MISSING version={version_id}"
                )
            for row in self.validate_rows(
                    receipt["asset_id"], receipt["root"], receipt.get("parts") or []):
                if row[8] in protected_blobs:
                    continue
                item = candidates.setdefault(row[8], {
                    "blob_id": row[8], "cloud_relative_path": row[9],
                    "encrypted_bytes": int(row[6]), "encrypted_sha256": row[7],
                    "superseded_versions": [],
                })
                item["superseded_versions"].append(version_id)
        return sorted(candidates.values(), key=lambda row: row["blob_id"])


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("stage-ledger")
    stage.add_argument("--asset", required=True)
    stage.add_argument("--root", required=True)
    commit = sub.add_parser("commit")
    commit.add_argument("--asset", required=True)
    commit.add_argument("--root", required=True)
    commit.add_argument("--version-id")
    sub.add_parser("bootstrap-confirmed")
    sub.add_parser("status")
    sub.add_parser("gc-plan")
    args = parser.parse_args()
    store = VersionStore()
    if args.command == "stage-ledger":
        result = store.stage(args.asset, args.root,
                             store.latest_ledger_rows(args.asset, args.root))
    elif args.command == "commit":
        result = store.commit(args.asset, args.root, args.version_id)
    elif args.command == "bootstrap-confirmed":
        result = store.bootstrap_confirmed()
    elif args.command == "status":
        result = store.status()
    else:
        result = {"candidates": store.gc_candidates()}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except VersionRefused as exc:
        print(str(exc))
        raise SystemExit(2)
