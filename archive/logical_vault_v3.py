#!/usr/bin/env python3
"""Logical Vault v3: semantic pages backed by natural-size CAS objects.

The page presented to an agent is a workspace snapshot, tool capsule, or
immutable artifact.  The bytes moved to/from Baidu are the page's natural
files.  A transport-sized constant is intentionally absent: one source file is
one encrypted content object, regardless of whether it is 2 KiB or 1.3 GiB.

The v2 vault remains an independent fallback.  This program never deletes v2
cloud objects or source bytes.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import fcntl
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Iterator

from baidu_client_download import (
    DOWNLOAD_ROOT, DownloadRefused, _single_account_db, download_cloud_file,
)
from vault_v2_stream import INCOMING, KEY, STAGE, sha256_file, vault_writer_busy, wait_cloud, pager_priority_reason


WS = Path(__file__).resolve().parent
DB = WS / "logical_vault_v3.sqlite3"
EVENTS = WS / "logical_vault_v3_events.jsonl"
LOCK = WS / ".logical_vault_v3.lock"
SYNC = WS / "vault_v2_sync.py"
# (incident note) Written by workspace_pager_maintenance.publish_pager_priority:
# the pager needs the single Baidu writer; upload stops at its next window boundary.
PAGER_PRIORITY_FLAG = WS / ".pager_priority"
CLOUD_BASE = os.environ.get("COLDSTORE_CLOUD_BASE", "/ColdArchive")
REMOTE_hostb = os.environ.get("COLDSTORE_REMOTE", "user@host-b")
BUF = 8 * 1024 * 1024
SCHEMA_VERSION = 2
KINDS = {"tool_capsule", "workspace_snapshot", "immutable_artifact"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+@/-]{0,511}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_DIGESTS = {"sha1": 40, "sha256": 64}


class VaultRefused(RuntimeError):
    """A fail-closed invariant rejected the requested operation."""


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(BUF), b""):
            h.update(block)
    return h.hexdigest()


def validate_sha256(value: str, field: str = "sha256") -> str:
    value = str(value).lower()
    if not SHA256_RE.fullmatch(value):
        raise VaultRefused(f"REFUSE_BAD_{field.upper()} value={value!r}")
    return value


def validate_source_digest(algorithm: str, value: str) -> str:
    algorithm = str(algorithm).lower()
    value = str(value).lower()
    expected_length = SOURCE_DIGESTS.get(algorithm)
    if expected_length is None or len(value) != expected_length or not re.fullmatch(r"[0-9a-f]+", value):
        raise VaultRefused(
            f"REFUSE_BAD_SOURCE_DIGEST algorithm={algorithm!r} value={value!r}"
        )
    return value


def source_hashes(host: str, source_path: str) -> dict[str, Any]:
    """Read one source once and return size, SHA-1, and SHA-256."""
    if host == "mac":
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0
        with Path(source_path).open("rb") as source:
            for block in iter(lambda: source.read(BUF), b""):
                sha1.update(block)
                sha256.update(block)
                size += len(block)
        return {"bytes": size, "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
    encoded_path = base64.b64encode(source_path.encode("utf-8")).decode("ascii")
    script = (
        "import base64,hashlib,json,sys;"
        "p=base64.b64decode(sys.argv[1]).decode();"
        "a=hashlib.sha1();b=hashlib.sha256();n=0;"
        "f=open(p,'rb');"
        "exec(\"while True:\\n x=f.read(8388608)\\n if not x: break\\n a.update(x);b.update(x);n+=len(x)\");"
        "f.close();print(json.dumps({'bytes':n,'sha1':a.hexdigest(),'sha256':b.hexdigest()}))"
    )
    command = f"exec python3 -c {shlex.quote(script)} {shlex.quote(encoded_path)}"
    completed = subprocess.run(
        ["ssh", "-n", host, command], text=True, capture_output=True, timeout=3600,
    )
    if completed.returncode:
        raise VaultRefused(
            f"REFUSE_SOURCE_HASH_FAILED host={host} path={source_path} detail={completed.stderr[-2000:]}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise VaultRefused(
            f"REFUSE_SOURCE_HASH_BAD_OUTPUT host={host} path={source_path} output={completed.stdout[-1000:]}"
        ) from exc
    if set(result) != {"bytes", "sha1", "sha256"}:
        raise VaultRefused(f"REFUSE_SOURCE_HASH_FIELDS path={source_path}")
    return result


def validate_id(value: str, field: str) -> str:
    value = str(value)
    if not SAFE_ID.fullmatch(value) or ".." in PurePosixPath(value).parts:
        raise VaultRefused(f"REFUSE_BAD_{field.upper()} value={value!r}")
    return value


def validate_opaque_id(value: str, field: str) -> str:
    value = str(value)
    if not value or len(value) > 1024 or any(ord(character) < 32 for character in value):
        raise VaultRefused(f"REFUSE_BAD_{field.upper()} value={value!r}")
    return value


def safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise VaultRefused(f"REFUSE_BAD_RELATIVE_PATH value={value!r}")
    return str(path)


def object_token(key_bytes: bytes, digest: str, plain_bytes: int) -> str:
    message = f"logical-vault-v3\0sha256\0{digest}\0{plain_bytes}".encode("utf-8")
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def object_cloud_relpath(key_bytes: bytes, digest: str, plain_bytes: int) -> str:
    token = object_token(key_bytes, digest, plain_bytes)
    return str(PurePosixPath("v3") / "objects" / token[:2] / f"{token}.blob")


def read_key(path: Path = KEY) -> bytes:
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise VaultRefused(f"REFUSE_KEY_MISSING_OR_PERMISSIONS path={path}")
    value = path.read_bytes()
    if not value:
        raise VaultRefused("REFUSE_EMPTY_KEY")
    return value


def connect(db_path: Path = DB) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects(
  digest TEXT PRIMARY KEY CHECK(length(digest)=64),
  plain_bytes INTEGER NOT NULL CHECK(plain_bytes>=0),
  cloud_relpath TEXT NOT NULL UNIQUE,
  encrypted_bytes INTEGER CHECK(encrypted_bytes>=0),
  encrypted_sha256 TEXT CHECK(encrypted_sha256 IS NULL OR length(encrypted_sha256)=64),
  cloud_state TEXT NOT NULL CHECK(cloud_state IN ('REGISTERED','UPLOADING','CLOUD_CONFIRMED','FAILED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS object_sources(
  digest TEXT NOT NULL REFERENCES objects(digest) ON DELETE RESTRICT,
  host TEXT NOT NULL,
  source_path TEXT NOT NULL,
  source_state TEXT NOT NULL CHECK(source_state IN ('PRESENT_UNVERIFIED','HASH_VERIFIED','MISSING')),
  last_verified_at TEXT,
  PRIMARY KEY(digest,host,source_path)
);
CREATE TABLE IF NOT EXISTS units(
  unit_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('tool_capsule','workspace_snapshot','immutable_artifact')),
  batch_id TEXT,
  family_id TEXT,
  name TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64),
  metadata_json TEXT NOT NULL,
  unit_state TEXT NOT NULL CHECK(unit_state IN ('REGISTERED','PARTIAL_CLOUD','CLOUD_CONFIRMED','RESTORE_VERIFIED')),
  temperature TEXT NOT NULL DEFAULT 'WARM' CHECK(temperature IN ('HOT','WARM','COLD','PINNED','ISOLATED')),
  pinned INTEGER NOT NULL DEFAULT 0,
  local_present INTEGER NOT NULL DEFAULT 1,
  last_access REAL,
  lease_until REAL,
  access_count INTEGER NOT NULL DEFAULT 0,
  access_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unit_entries(
  unit_id TEXT NOT NULL REFERENCES units(unit_id) ON DELETE RESTRICT,
  digest TEXT REFERENCES objects(digest) ON DELETE RESTRICT,
  logical_path TEXT NOT NULL,
  entry_type TEXT NOT NULL CHECK(entry_type IN ('file','directory','symlink')),
  role TEXT NOT NULL,
  mode INTEGER NOT NULL CHECK(mode>=0),
  link_target TEXT,
  ordinal INTEGER NOT NULL,
  PRIMARY KEY(unit_id,logical_path),
  UNIQUE(unit_id,ordinal),
  CHECK((entry_type='file' AND digest IS NOT NULL AND link_target IS NULL) OR
        (entry_type='directory' AND digest IS NULL AND link_target IS NULL) OR
        (entry_type='symlink' AND digest IS NULL AND link_target IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS unit_dependencies(
  unit_id TEXT NOT NULL REFERENCES units(unit_id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL,
  raw_requirement TEXT NOT NULL,
  dependency_name TEXT NOT NULL,
  PRIMARY KEY(unit_id,ordinal)
);
CREATE TABLE IF NOT EXISTS capabilities(
  capability_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_units(
  capability_id TEXT NOT NULL REFERENCES capabilities(capability_id) ON DELETE RESTRICT,
  unit_id TEXT NOT NULL REFERENCES units(unit_id) ON DELETE RESTRICT,
  relation TEXT NOT NULL,
  PRIMARY KEY(capability_id,unit_id)
);
CREATE TABLE IF NOT EXISTS batches(
  batch_id TEXT PRIMARY KEY,
  mapping_sha256 TEXT NOT NULL CHECK(length(mapping_sha256)=64),
  expected_units INTEGER NOT NULL CHECK(expected_units>=0),
  expected_plain_bytes INTEGER NOT NULL CHECK(expected_plain_bytes>=0),
  batch_state TEXT NOT NULL CHECK(batch_state IN ('REGISTERED','PARTIAL_CLOUD','CLOUD_CONFIRMED','AUDIT_PASS')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_units_batch ON units(batch_id);
CREATE INDEX IF NOT EXISTS idx_units_family ON units(family_id);
CREATE INDEX IF NOT EXISTS idx_objects_state ON objects(cloud_state);
CREATE INDEX IF NOT EXISTS idx_unit_entries_digest ON unit_entries(digest);
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    current = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if current and int(current[0]) not in (1, SCHEMA_VERSION):
        raise VaultRefused(
            f"REFUSE_SCHEMA_VERSION supported=1,{SCHEMA_VERSION} actual={current[0]}"
        )
    columns = {row[1] for row in conn.execute("PRAGMA table_info(units)")}
    migrations = {
        "temperature": "ALTER TABLE units ADD COLUMN temperature TEXT NOT NULL DEFAULT 'WARM'",
        "pinned": "ALTER TABLE units ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
        "local_present": "ALTER TABLE units ADD COLUMN local_present INTEGER NOT NULL DEFAULT 1",
        "last_access": "ALTER TABLE units ADD COLUMN last_access REAL",
        "lease_until": "ALTER TABLE units ADD COLUMN lease_until REAL",
        "access_count": "ALTER TABLE units ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0",
        "access_reason": "ALTER TABLE units ADD COLUMN access_reason TEXT",
    }
    for name, statement in migrations.items():
        if name not in columns:
            conn.execute(statement)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
        (str(SCHEMA_VERSION),),
    )
    conn.execute("UPDATE units SET last_access=COALESCE(last_access,?)", (time.time(),))
    conn.commit()


@contextlib.contextmanager
def writer_lock(path: Path = LOCK) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def record_event(
    conn: sqlite3.Connection,
    event_type: str,
    subject_id: str,
    detail: dict[str, Any],
) -> None:
    stamp = now()
    payload = canonical_json(detail)
    conn.execute(
        "INSERT INTO events(occurred_at,event_type,subject_id,detail_json) VALUES(?,?,?,?)",
        (stamp, event_type, subject_id, payload),
    )


def export_events(conn: sqlite3.Connection, events_path: Path | None = None) -> None:
    """Export committed events atomically; rolled-back rows never leak."""
    events_path = events_path or EVENTS
    events_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = events_path.parent / f".{events_path.name}.{os.getpid()}.tmp"
    with temporary.open("w", encoding="utf-8") as output:
        for row in conn.execute(
            "SELECT occurred_at,event_type,subject_id,detail_json FROM events ORDER BY event_id"
        ):
            output.write(canonical_json({
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "subject_id": row["subject_id"],
                "detail": json.loads(row["detail_json"]),
            }) + "\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, events_path)


def dependency_name(raw: str) -> str:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)", raw)
    return match.group(1).lower() if match else raw.strip().lower()


def logical_package_filename(row: dict[str, Any]) -> str:
    evidence = row.get("archive_evidence") or {}
    archive_format = str(evidence.get("archive_format") or "")
    extension = ".conda" if "conda_v2" in archive_format else ".tar.bz2" if "tar_bz2" in archive_format else ".blob"
    fields = [row.get("logical_package_name") or "package", row.get("version"), row.get("build"), row.get("platform")]
    stem = "-".join(str(x) for x in fields if x not in (None, ""))
    stem = re.sub(r"[^A-Za-z0-9._+-]+", "_", stem).strip("._")
    return safe_relative_path(f"package/{stem}{extension}")


def unit_manifest(
    unit_id: str,
    kind: str,
    metadata: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    dependencies: Iterable[str],
) -> dict[str, Any]:
    return {
        "schema": "logical-vault-unit-v3",
        "unit_id": unit_id,
        "kind": kind,
        "metadata": metadata,
        "entries": list(entries),
        "dependencies": list(dependencies),
    }


def manifest_hash(manifest: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(manifest).encode("utf-8"))


def manifest_from_db(conn: sqlite3.Connection, unit_id: str) -> dict[str, Any]:
    unit = conn.execute("SELECT * FROM units WHERE unit_id=?", (unit_id,)).fetchone()
    if not unit:
        raise VaultRefused(f"REFUSE_UNKNOWN_UNIT unit_id={unit_id}")
    entries = [dict(row) for row in conn.execute(
        "SELECT ue.logical_path,ue.entry_type,ue.role,ue.mode,ue.link_target,ue.ordinal,"
        "ue.digest,o.plain_bytes FROM unit_entries ue LEFT JOIN objects o USING(digest) "
        "WHERE ue.unit_id=? ORDER BY ue.ordinal",
        (unit_id,),
    )]
    for item in entries:
        item.pop("ordinal", None)
        if item["entry_type"] != "file":
            item.pop("digest", None)
            item.pop("plain_bytes", None)
        if item["entry_type"] != "symlink":
            item.pop("link_target", None)
    dependencies = [row[0] for row in conn.execute(
        "SELECT raw_requirement FROM unit_dependencies WHERE unit_id=? ORDER BY ordinal",
        (unit_id,),
    )]
    metadata = json.loads(unit["metadata_json"])
    return unit_manifest(unit_id, unit["kind"], metadata, entries, dependencies)


def assert_manifest(conn: sqlite3.Connection, unit_id: str) -> dict[str, Any]:
    unit = conn.execute("SELECT manifest_sha256 FROM units WHERE unit_id=?", (unit_id,)).fetchone()
    manifest = manifest_from_db(conn, unit_id)
    actual = manifest_hash(manifest)
    if actual != unit[0]:
        raise VaultRefused(
            f"REFUSE_MANIFEST_DRIFT unit_id={unit_id} expected={unit[0]} actual={actual}"
        )
    return manifest


def insert_object(
    conn: sqlite3.Connection,
    key_bytes: bytes,
    digest: str,
    plain_bytes: int,
    host: str,
    source_path: str,
    source_state: str = "PRESENT_UNVERIFIED",
) -> None:
    digest = validate_sha256(digest)
    if int(plain_bytes) < 0:
        raise VaultRefused(f"REFUSE_NEGATIVE_SIZE digest={digest} bytes={plain_bytes}")
    existing = conn.execute("SELECT plain_bytes,cloud_relpath FROM objects WHERE digest=?", (digest,)).fetchone()
    cloud_relpath = object_cloud_relpath(key_bytes, digest, int(plain_bytes))
    if existing and (int(existing[0]) != int(plain_bytes) or existing[1] != cloud_relpath):
        raise VaultRefused(f"REFUSE_OBJECT_IDENTITY_COLLISION digest={digest}")
    stamp = now()
    conn.execute(
        "INSERT OR IGNORE INTO objects(digest,plain_bytes,cloud_relpath,cloud_state,created_at,updated_at) "
        "VALUES(?,?,?,'REGISTERED',?,?)",
        (digest, int(plain_bytes), cloud_relpath, stamp, stamp),
    )
    conn.execute(
        "INSERT OR IGNORE INTO object_sources(digest,host,source_path,source_state) VALUES(?,?,?,?)",
        (digest, host, source_path, source_state),
    )


def insert_unit(
    conn: sqlite3.Connection,
    *,
    key_bytes: bytes,
    unit_id: str,
    kind: str,
    batch_id: str | None,
    family_id: str | None,
    name: str,
    metadata: dict[str, Any],
    objects: list[dict[str, Any]],
    dependencies: list[str],
    source_host: str,
) -> None:
    validate_id(unit_id, "unit_id")
    if kind not in KINDS:
        raise VaultRefused(f"REFUSE_BAD_KIND value={kind}")
    if not objects:
        raise VaultRefused(f"REFUSE_EMPTY_UNIT unit_id={unit_id}")
    canonical_entries = []
    seen_paths = set()
    for ordinal, item in enumerate(objects):
        logical_path = safe_relative_path(item["logical_path"])
        if logical_path in seen_paths:
            raise VaultRefused(f"REFUSE_DUPLICATE_LOGICAL_PATH unit={unit_id} path={logical_path}")
        seen_paths.add(logical_path)
        entry_type = str(item.get("entry_type") or "file")
        if entry_type not in ("file", "directory", "symlink"):
            raise VaultRefused(f"REFUSE_BAD_ENTRY_TYPE unit={unit_id} type={entry_type}")
        canonical_entry = {
            "logical_path": logical_path,
            "entry_type": entry_type,
            "role": str(item.get("role") or "content"),
            "mode": int(item.get("mode", 0o644 if entry_type == "file" else 0o755)),
        }
        if entry_type == "file":
            digest = validate_sha256(item["digest"])
            plain_bytes = int(item["plain_bytes"])
            insert_object(
                conn, key_bytes, digest, plain_bytes, source_host,
                str(item["source_path"]), str(item.get("source_state") or "PRESENT_UNVERIFIED"),
            )
            canonical_entry.update({"digest": digest, "plain_bytes": plain_bytes})
        elif entry_type == "symlink":
            link_target = str(item.get("link_target") or "")
            if not link_target or "\x00" in link_target:
                raise VaultRefused(f"REFUSE_BAD_LINK_TARGET unit={unit_id} path={logical_path}")
            canonical_entry["link_target"] = link_target
        canonical_entries.append(canonical_entry)
    manifest = unit_manifest(unit_id, kind, metadata, canonical_entries, dependencies)
    digest_manifest = manifest_hash(manifest)
    existing = conn.execute("SELECT manifest_sha256 FROM units WHERE unit_id=?", (unit_id,)).fetchone()
    if existing and existing[0] != digest_manifest:
        raise VaultRefused(
            f"REFUSE_UNIT_REDEFINITION unit_id={unit_id} existing={existing[0]} new={digest_manifest}"
        )
    stamp = now()
    conn.execute(
        "INSERT OR IGNORE INTO units(unit_id,kind,batch_id,family_id,name,manifest_sha256,metadata_json,unit_state,last_access,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,'REGISTERED',?,?,?)",
        (unit_id, kind, batch_id, family_id, name, digest_manifest,
         canonical_json(metadata), time.time(), stamp, stamp),
    )
    for ordinal, item in enumerate(canonical_entries):
        conn.execute(
            "INSERT OR IGNORE INTO unit_entries(unit_id,digest,logical_path,entry_type,role,mode,link_target,ordinal) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (unit_id, item.get("digest"), item["logical_path"], item["entry_type"],
             item["role"], item["mode"], item.get("link_target"), ordinal),
        )
    for ordinal, raw in enumerate(dependencies):
        conn.execute(
            "INSERT OR IGNORE INTO unit_dependencies(unit_id,ordinal,raw_requirement,dependency_name) VALUES(?,?,?,?)",
            (unit_id, ordinal, raw, dependency_name(raw)),
        )
    if family_id:
        capability_id = validate_opaque_id(family_id, "capability_id")
        conn.execute(
            "INSERT OR IGNORE INTO capabilities(capability_id,name,metadata_json) VALUES(?,?,?)",
            (capability_id, name, canonical_json({"family_id": family_id})),
        )
        conn.execute(
            "INSERT OR IGNORE INTO capability_units(capability_id,unit_id,relation) VALUES(?,?,'implementation')",
            (capability_id, unit_id),
        )


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8", errors="strict") as source:
        for line_number, line in enumerate(source, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VaultRefused(f"REFUSE_BAD_JSON line={line_number} detail={exc}") from exc
            if not isinstance(row, dict):
                raise VaultRefused(f"REFUSE_NONOBJECT_JSON line={line_number}")
            rows.append(row)
    return rows


def register_function_batch(
    conn: sqlite3.Connection,
    key_bytes: bytes,
    batch_id: str,
    mapping_path: Path,
    source_root: str,
    source_host: str,
) -> dict[str, Any]:
    batch_id = validate_id(batch_id, "batch_id")
    if not mapping_path.is_file():
        raise VaultRefused(f"REFUSE_MAPPING_MISSING path={mapping_path}")
    rows = load_jsonl(mapping_path)
    if not rows:
        raise VaultRefused("REFUSE_EMPTY_MAPPING")
    mapping_sha = file_sha256(mapping_path)
    total_bytes = 0
    seen_units = set()
    with conn:
        for line_number, row in enumerate(rows, 1):
            required = ["unit_id", "digest", "bytes", "object_relpath", "logical_package_name"]
            missing = [field for field in required if field not in row]
            if missing:
                raise VaultRefused(f"REFUSE_MAPPING_FIELDS line={line_number} missing={missing}")
            if row.get("batch_id") != batch_id:
                raise VaultRefused(
                    f"REFUSE_BATCH_MISMATCH line={line_number} expected={batch_id} actual={row.get('batch_id')}"
                )
            unit_id = validate_id(str(row["unit_id"]), "unit_id")
            if unit_id in seen_units:
                raise VaultRefused(f"REFUSE_DUPLICATE_UNIT line={line_number} unit_id={unit_id}")
            seen_units.add(unit_id)
            object_relpath = safe_relative_path(str(row["object_relpath"]))
            source_path = str(PurePosixPath(source_root) / object_relpath)
            source_algorithm = str(row.get("digest_algorithm") or "sha256").lower()
            source_digest = validate_source_digest(source_algorithm, row["digest"])
            if source_algorithm == "sha256":
                content_sha256 = source_digest
            else:
                hashes = source_hashes(source_host, source_path)
                if int(hashes["bytes"]) != int(row["bytes"]) or hashes[source_algorithm] != source_digest:
                    raise VaultRefused(
                        f"REFUSE_SOURCE_IDENTITY_MISMATCH line={line_number} path={source_path} "
                        f"expected_bytes={row['bytes']} actual_bytes={hashes['bytes']} "
                        f"expected_{source_algorithm}={source_digest} actual_{source_algorithm}={hashes[source_algorithm]}"
                    )
                content_sha256 = validate_sha256(hashes["sha256"])
            index = ((row.get("archive_evidence") or {}).get("index") or {})
            dependencies = index.get("depends") or row.get("depends") or []
            if not isinstance(dependencies, list) or any(not isinstance(x, str) for x in dependencies):
                raise VaultRefused(f"REFUSE_BAD_DEPENDENCIES line={line_number}")
            metadata = {
                "schema": row.get("schema"),
                "batch_id": batch_id,
                "family_id": row.get("family_id"),
                "logical_package_name": row["logical_package_name"],
                "ecosystem": row.get("ecosystem"),
                "version": row.get("version"),
                "build": row.get("build"),
                "platform": row.get("platform"),
                "source_id": row.get("source_id"),
                "evidence_fingerprint": (row.get("archive_evidence") or {}).get("evidence_fingerprint"),
                "depends_count": index.get("depends_count"),
                "depends_sha256": index.get("depends_sha256"),
                "source_digest_algorithm": source_algorithm,
                "source_digest": source_digest,
                "content_sha256": content_sha256,
            }
            size = int(row["bytes"])
            insert_unit(
                conn,
                key_bytes=key_bytes,
                unit_id=unit_id,
                kind="tool_capsule",
                batch_id=batch_id,
                family_id=row.get("family_id"),
                name=str(row["logical_package_name"]),
                metadata=metadata,
                objects=[{
                    "logical_path": logical_package_filename(row),
                    "role": "package_archive",
                    "digest": content_sha256,
                    "plain_bytes": size,
                    "source_path": source_path,
                }],
                dependencies=dependencies,
                source_host=source_host,
            )
            total_bytes += size
        existing = conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        identity = (mapping_sha, len(rows), total_bytes)
        if existing and (existing["mapping_sha256"], existing["expected_units"], existing["expected_plain_bytes"]) != identity:
            raise VaultRefused(f"REFUSE_BATCH_REDEFINITION batch_id={batch_id}")
        stamp = now()
        conn.execute(
            "INSERT OR IGNORE INTO batches(batch_id,mapping_sha256,expected_units,expected_plain_bytes,batch_state,created_at,updated_at) "
            "VALUES(?,?,?,?,'REGISTERED',?,?)",
            (batch_id, mapping_sha, len(rows), total_bytes, stamp, stamp),
        )
        record_event(conn, "FUNCTION_BATCH_REGISTERED", batch_id, {
            "mapping_sha256": mapping_sha,
            "units": len(rows),
            "plain_bytes": total_bytes,
            "object_granularity": "natural_file",
        })
    return {
        "verdict": "REGISTER_FUNCTION_BATCH_PASS",
        "batch_id": batch_id,
        "units": len(rows),
        "plain_bytes": total_bytes,
        "mapping_sha256": mapping_sha,
    }


def register_tree(
    conn: sqlite3.Connection,
    key_bytes: bytes,
    unit_id: str,
    kind: str,
    source_root: Path,
    snapshot_proof: Path | None,
    name: str | None = None,
) -> dict[str, Any]:
    if kind == "workspace_snapshot" and snapshot_proof is None:
        raise VaultRefused("REFUSE_WORKSPACE_WITHOUT_SNAPSHOT_PROOF")
    if snapshot_proof is not None:
        proof = json.loads(snapshot_proof.read_text(encoding="utf-8"))
        if proof.get("verdict") not in ("PASS", "SNAPSHOT_PASS", "CONSISTENCY_PASS"):
            raise VaultRefused("REFUSE_BAD_SNAPSHOT_PROOF")
    else:
        proof = None
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise VaultRefused(f"REFUSE_TREE_MISSING path={source_root}")
    existing_workspaces = conn.execute(
        "SELECT unit_id,metadata_json FROM units WHERE kind='workspace_snapshot'"
    ).fetchall()
    for existing in existing_workspaces:
        other_raw = json.loads(existing["metadata_json"]).get("source_root")
        if not other_raw:
            continue
        other = Path(other_raw)
        if source_root == other or source_root in other.parents or other in source_root.parents:
            raise VaultRefused(
                f"REFUSE_OVERLAPPING_WORKSPACE_OWNERSHIP new={source_root} existing_unit={existing['unit_id']} existing={other}"
            )
    paths = sorted(source_root.rglob("*"), key=lambda p: (len(p.relative_to(source_root).parts), p.as_posix()))
    if not paths:
        raise VaultRefused("REFUSE_EMPTY_TREE")
    objects = []
    for path in paths:
        relative = safe_relative_path(path.relative_to(source_root).as_posix())
        mode = path.lstat().st_mode & 0o7777
        if path.is_symlink():
            objects.append({
                "logical_path": relative, "entry_type": "symlink", "role": "workspace_link",
                "mode": mode, "link_target": os.readlink(path),
            })
        elif path.is_dir():
            objects.append({
                "logical_path": relative, "entry_type": "directory", "role": "workspace_directory",
                "mode": mode,
            })
        elif path.is_file():
            objects.append({
                "logical_path": relative,
                "entry_type": "file",
                "role": "workspace_file" if kind == "workspace_snapshot" else "artifact_file",
                "mode": mode,
                "digest": file_sha256(path),
                "plain_bytes": path.stat().st_size,
                "source_path": str(path),
                "source_state": "HASH_VERIFIED",
            })
        else:
            raise VaultRefused(f"REFUSE_UNSUPPORTED_TREE_ENTRY path={path}")
    metadata = {
        "source_root": str(source_root),
        "snapshot_proof_sha256": file_sha256(snapshot_proof) if snapshot_proof else None,
    }
    with conn:
        insert_unit(
            conn, key_bytes=key_bytes, unit_id=unit_id, kind=kind,
            batch_id=None, family_id=None, name=name or source_root.name,
            metadata=metadata, objects=objects, dependencies=[], source_host="mac",
        )
        record_event(conn, "TREE_REGISTERED", unit_id, {
            "kind": kind, "entries": len(objects),
            "plain_bytes": sum(x.get("plain_bytes", 0) for x in objects),
        })
    return {
        "verdict": "REGISTER_TREE_PASS", "unit_id": unit_id, "kind": kind,
        "entries": len(objects),
        "objects": sum(x["entry_type"] == "file" for x in objects),
        "unique_objects": len({x["digest"] for x in objects if x["entry_type"] == "file"}),
        "plain_bytes": sum(x.get("plain_bytes", 0) for x in objects),
    }


def remote_reader(host: str, source_path: str) -> subprocess.Popen:
    command = f"exec /bin/cat -- {shlex.quote(source_path)}"
    return subprocess.Popen(
        ["ssh", host, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )


@contextlib.contextmanager
def source_stream(host: str, source_path: str) -> Iterator[BinaryIO]:
    if host == "mac":
        with Path(source_path).open("rb") as stream:
            yield stream
        return
    process = remote_reader(host, source_path)
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        yield process.stdout
        process.stdout.close()
        detail = process.stderr.read().decode("utf-8", errors="replace")[-2000:]
        process.stderr.close()
        if process.wait() != 0:
            raise VaultRefused(f"REFUSE_REMOTE_READ_FAILED host={host} path={source_path} detail={detail}")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise


def encrypt_source(
    host: str,
    source_path: str,
    expected_bytes: int,
    expected_digest: str,
    output: Path,
    key_path: Path = KEY,
) -> tuple[int, str, int, str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise VaultRefused(f"REFUSE_ENCRYPT_OUTPUT_EXISTS path={output}")
    gpg = subprocess.Popen([
        "/usr/local/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
        "--passphrase-file", str(key_path), "--symmetric", "--cipher-algo", "AES256",
        "--compress-algo", "none", "--output", str(output),
    ], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert gpg.stdin is not None
    assert gpg.stderr is not None
    plain_hash = hashlib.sha256()
    plain_bytes = 0
    try:
        with source_stream(host, source_path) as stream:
            for block in iter(lambda: stream.read(BUF), b""):
                gpg.stdin.write(block)
                plain_hash.update(block)
                plain_bytes += len(block)
        gpg.stdin.close()
        detail = gpg.stderr.read().decode("utf-8", errors="replace")[-2000:]
        gpg.stderr.close()
        if gpg.wait() != 0:
            raise VaultRefused(f"REFUSE_GPG_ENCRYPT_FAILED detail={detail}")
        actual_digest = plain_hash.hexdigest()
        if plain_bytes != int(expected_bytes) or actual_digest != expected_digest:
            raise VaultRefused(
                f"REFUSE_SOURCE_DRIFT path={source_path} expected_bytes={expected_bytes} actual_bytes={plain_bytes} "
                f"expected_sha256={expected_digest} actual_sha256={actual_digest}"
            )
        encrypted_bytes = output.stat().st_size
        encrypted_digest = file_sha256(output)
        return plain_bytes, actual_digest, encrypted_bytes, encrypted_digest
    except BaseException:
        if not gpg.stdin.closed:
            gpg.stdin.close()
        if gpg.poll() is None:
            gpg.kill()
        gpg.wait()
        output.unlink(missing_ok=True)
        raise


def select_objects(
    conn: sqlite3.Connection,
    batch_id: str | None,
    unit_id: str | None,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    clauses = ["o.cloud_state!='CLOUD_CONFIRMED'"]
    params: list[Any] = []
    if batch_id:
        clauses.append("u.batch_id=?")
        params.append(batch_id)
    if unit_id:
        clauses.append("u.unit_id=?")
        params.append(unit_id)
    sql = (
        "SELECT DISTINCT o.* FROM objects o JOIN unit_entries ue USING(digest) "
        "JOIN units u ON u.unit_id=ue.unit_id WHERE " + " AND ".join(clauses) +
        " ORDER BY o.plain_bytes DESC,o.digest"
    )
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))
    return list(conn.execute(sql, params))


def verify_encrypted_plaintext(
    blob: Path,
    expected_bytes: int,
    expected_digest: str,
    key_path: Path = KEY,
) -> tuple[int, str]:
    """Prove an interrupted staged ciphertext still contains the exact object."""
    process = subprocess.Popen([
        "/usr/local/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
        "--passphrase-file", str(key_path), "--decrypt", str(blob),
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    assert process.stdout is not None
    assert process.stderr is not None
    digest = hashlib.sha256()
    size = 0
    try:
        for block in iter(lambda: process.stdout.read(BUF), b""):
            digest.update(block)
            size += len(block)
        process.stdout.close()
        detail = process.stderr.read().decode("utf-8", errors="replace")[-2000:]
        process.stderr.close()
        if process.wait() != 0:
            raise VaultRefused(f"REFUSE_STAGED_GPG_FAILED detail={detail}")
        actual = digest.hexdigest()
        if size != int(expected_bytes) or actual != expected_digest:
            raise VaultRefused(
                f"REFUSE_STAGED_PLAINTEXT_DRIFT expected_bytes={expected_bytes} actual_bytes={size} "
                f"expected_sha256={expected_digest} actual_sha256={actual}"
            )
        return size, actual
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise


def refresh_states(conn: sqlite3.Connection, digest: str | None = None) -> None:
    """Refresh aggregates, optionally just those referencing a changed object.

    An object can be shared across units and batches. Update every referencing
    unit in the same transaction as its cloud receipt, without rewriting all
    unrelated units for each small file.
    """
    stamp = now()
    unit_filter = ""
    batch_filter = ""
    params: tuple[Any, ...] = (stamp,)
    if digest is not None:
        unit_filter = " WHERE unit_id IN (SELECT unit_id FROM unit_entries WHERE digest=?)"
        batch_filter = (
            " WHERE batch_id IN (SELECT u.batch_id FROM units u "
            "JOIN unit_entries ue USING(unit_id) WHERE ue.digest=?)"
        )
        params += (digest,)
    conn.execute(
        "UPDATE units SET unit_state=CASE "
        "WHEN NOT EXISTS(SELECT 1 FROM unit_entries ue JOIN objects o USING(digest) WHERE ue.unit_id=units.unit_id AND o.cloud_state!='CLOUD_CONFIRMED') THEN "
        "CASE WHEN unit_state='RESTORE_VERIFIED' THEN 'RESTORE_VERIFIED' ELSE 'CLOUD_CONFIRMED' END "
        "WHEN EXISTS(SELECT 1 FROM unit_entries ue JOIN objects o USING(digest) WHERE ue.unit_id=units.unit_id AND o.cloud_state='CLOUD_CONFIRMED') THEN 'PARTIAL_CLOUD' "
        "ELSE 'REGISTERED' END, updated_at=?" + unit_filter,
        params,
    )
    conn.execute(
        "UPDATE batches SET batch_state=CASE "
        "WHEN NOT EXISTS(SELECT 1 FROM units u WHERE u.batch_id=batches.batch_id AND u.unit_state NOT IN ('CLOUD_CONFIRMED','RESTORE_VERIFIED')) THEN "
        "CASE WHEN batch_state='AUDIT_PASS' THEN 'AUDIT_PASS' ELSE 'CLOUD_CONFIRMED' END "
        "WHEN EXISTS(SELECT 1 FROM units u WHERE u.batch_id=batches.batch_id AND u.unit_state IN ('PARTIAL_CLOUD','CLOUD_CONFIRMED','RESTORE_VERIFIED')) THEN 'PARTIAL_CLOUD' "
        "ELSE 'REGISTERED' END, updated_at=?" + batch_filter,
        params,
    )


def stage_object(conn: sqlite3.Connection, row: sqlite3.Row, key_path: Path = KEY) -> dict[str, Any]:
    """Encrypt and announce one natural object; resumable before cloud confirm."""
    digest = row["digest"]
    if row["cloud_state"] == "CLOUD_CONFIRMED":
        return {
            "verdict": "UPLOAD_REUSED", "digest": digest,
            "plain_bytes": row["plain_bytes"], "already_confirmed": True,
        }
    source = conn.execute(
        "SELECT host,source_path FROM object_sources WHERE digest=? AND source_state!='MISSING' "
        "ORDER BY CASE source_state WHEN 'HASH_VERIFIED' THEN 0 ELSE 1 END,host,source_path LIMIT 1",
        (digest,),
    ).fetchone()
    if not source:
        raise VaultRefused(f"REFUSE_NO_SOURCE digest={digest}")
    token = PurePosixPath(row["cloud_relpath"]).stem
    temporary = INCOMING / f".{token}.{os.getpid()}.partial"
    destination = STAGE / row["cloud_relpath"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not row["encrypted_bytes"] or not row["encrypted_sha256"]:
            verify_encrypted_plaintext(
                destination, row["plain_bytes"], digest, key_path,
            )
            encrypted_bytes = destination.stat().st_size
            encrypted_digest = file_sha256(destination)
            with conn:
                conn.execute(
                    "UPDATE objects SET encrypted_bytes=?,encrypted_sha256=?,cloud_state='UPLOADING',updated_at=? WHERE digest=?",
                    (encrypted_bytes, encrypted_digest, now(), digest),
                )
                record_event(conn, "OBJECT_STAGE_RECOVERED", digest, {
                    "plain_bytes": row["plain_bytes"],
                    "encrypted_bytes": encrypted_bytes,
                    "encrypted_sha256": encrypted_digest,
                    "cloud_relpath": row["cloud_relpath"],
                })
            return {
                "verdict": "OBJECT_STAGE_RECOVERED", "digest": digest,
                "plain_bytes": row["plain_bytes"], "encrypted_bytes": encrypted_bytes,
                "encrypted_sha256": encrypted_digest,
                "cloud_relpath": row["cloud_relpath"], "destination": str(destination),
                "source_host": source["host"], "source_path": source["source_path"],
            }
        if (destination.stat().st_size != int(row["encrypted_bytes"])
                or file_sha256(destination) != row["encrypted_sha256"]):
            raise VaultRefused(f"REFUSE_STAGED_OBJECT_DRIFT path={destination}")
        return {
            "verdict": "OBJECT_STAGE_REUSED", "digest": digest,
            "plain_bytes": row["plain_bytes"], "encrypted_bytes": row["encrypted_bytes"],
            "encrypted_sha256": row["encrypted_sha256"],
            "cloud_relpath": row["cloud_relpath"], "destination": str(destination),
            "source_host": source["host"], "source_path": source["source_path"],
        }
    try:
        _, _, encrypted_bytes, encrypted_digest = encrypt_source(
            source["host"], source["source_path"], row["plain_bytes"], digest, temporary, key_path,
        )
        os.replace(temporary, destination)
        with conn:
            conn.execute(
                "UPDATE objects SET encrypted_bytes=?,encrypted_sha256=?,cloud_state='UPLOADING',updated_at=? WHERE digest=?",
                (encrypted_bytes, encrypted_digest, now(), digest),
            )
            record_event(conn, "OBJECT_STAGED", digest, {
                "plain_bytes": row["plain_bytes"], "encrypted_bytes": encrypted_bytes,
                "encrypted_sha256": encrypted_digest, "cloud_relpath": row["cloud_relpath"],
            })
        return {
            "verdict": "OBJECT_STAGED", "digest": digest,
            "plain_bytes": row["plain_bytes"], "encrypted_bytes": encrypted_bytes,
            "encrypted_sha256": encrypted_digest, "cloud_relpath": row["cloud_relpath"],
            "destination": str(destination), "source_host": source["host"],
            "source_path": source["source_path"],
        }
    except BaseException as exc:
        with conn:
            conn.execute("UPDATE objects SET cloud_state='FAILED',updated_at=? WHERE digest=?", (now(), digest))
            record_event(conn, "OBJECT_UPLOAD_FAILED", digest, {"error": str(exc)[:2000]})
        raise
    finally:
        temporary.unlink(missing_ok=True)


def confirm_staged_object(conn: sqlite3.Connection, prepared: dict[str, Any]) -> dict[str, Any]:
    if prepared.get("already_confirmed"):
        return prepared
    digest = prepared["digest"]
    destination = Path(prepared["destination"])
    try:
        wait_cloud(destination, int(prepared["encrypted_bytes"]), prepared["encrypted_sha256"])
        with conn:
            conn.execute(
                "UPDATE objects SET cloud_state='CLOUD_CONFIRMED',updated_at=? WHERE digest=?",
                (now(), digest),
            )
            conn.execute(
                "UPDATE object_sources SET source_state='HASH_VERIFIED',last_verified_at=? "
                "WHERE digest=? AND host=? AND source_path=?",
                (now(), digest, prepared["source_host"], prepared["source_path"]),
            )
            refresh_states(conn, digest=digest)
            record_event(conn, "OBJECT_CLOUD_CONFIRMED", digest, {
                "plain_bytes": prepared["plain_bytes"],
                "encrypted_bytes": prepared["encrypted_bytes"],
                "encrypted_sha256": prepared["encrypted_sha256"],
                "cloud_relpath": prepared["cloud_relpath"],
            })
        return {
            "verdict": "OBJECT_CLOUD_CONFIRMED", "digest": digest,
            "plain_bytes": prepared["plain_bytes"],
            "encrypted_bytes": prepared["encrypted_bytes"],
            "encrypted_sha256": prepared["encrypted_sha256"],
            "cloud_relpath": prepared["cloud_relpath"],
        }
    except BaseException as exc:
        with conn:
            conn.execute("UPDATE objects SET cloud_state='FAILED',updated_at=? WHERE digest=?", (now(), digest))
            record_event(conn, "OBJECT_UPLOAD_FAILED", digest, {"error": str(exc)[:2000]})
        raise
    finally:
        if conn.execute("SELECT cloud_state FROM objects WHERE digest=?", (digest,)).fetchone()[0] == "CLOUD_CONFIRMED":
            destination.unlink(missing_ok=True)


def upload_one(conn: sqlite3.Connection, row: sqlite3.Row, key_path: Path = KEY) -> dict[str, Any]:
    return confirm_staged_object(conn, stage_object(conn, row, key_path))


def upload_windows(rows: list[sqlite3.Row], window: int, max_window_bytes: int) -> Iterator[list[sqlite3.Row]]:
    if window < 1 or max_window_bytes < 1:
        raise VaultRefused("REFUSE_BAD_UPLOAD_WINDOW")
    current: list[sqlite3.Row] = []
    current_bytes = 0
    for row in rows:
        size = int(row["plain_bytes"])
        if current and (len(current) >= window or current_bytes + size > max_window_bytes):
            yield current
            current, current_bytes = [], 0
        current.append(row)
        current_bytes += size
    if current:
        yield current


def assert_stage_folder_free() -> None:
    """Refuse to stage while the v2 archiver owns the Baidu backup folder.

    The Baidu client's folder-backup watcher drops create events when several
    files land within seconds (<date> measurement: 3x178MB staged together ran
    at 0.28MB/s aggregate vs 3.27MB/s serial and the third file never registered),
    so the folder is single-writer by contract across v2 and v3.
    """
    busy = vault_writer_busy(exclude=(LOCK,))
    if busy:
        raise VaultRefused("REFUSE_STAGE_FOLDER_BUSY " + busy)


def pager_priority_yield(flag: Path | None = None) -> str | None:
    """Reason to hand the Baidu writer back to the workspace pager, or None.

    A window boundary is the only safe yield point: every object of the window
    has been cloud-confirmed and unlinked, so the staging folder holds none of
    ours and the pager's archiver can take the writer lock next. (incident note)
    """
    flag = PAGER_PRIORITY_FLAG if flag is None else Path(flag)
    return pager_priority_reason(flag)


def run_upload(
    conn: sqlite3.Connection,
    batch_id: str | None,
    unit_id: str | None,
    limit: int | None,
    sync_every: int,
    window: int,
    max_window_bytes: int,
) -> dict[str, Any]:
    selected = select_objects(conn, batch_id, unit_id, limit)
    results = []
    confirmed = 0
    yielded = None
    for rows in upload_windows(selected, window, max_window_bytes):
        yielded = pager_priority_yield()
        if yielded is not None:
            print(canonical_json({"verdict": "UPLOAD_YIELD_TO_PAGER", "reason": yielded,
                                  "confirmed_this_run": confirmed}), flush=True)
            break
        assert_stage_folder_free()
        try:
            prepared = []
            stage_error = None
            for row in rows:
                try:
                    prepared.append(stage_object(conn, row))
                except BaseException as exc:
                    stage_error = exc
                    break
            for item in prepared:
                result = confirm_staged_object(conn, item)
                results.append(result)
                confirmed += 1
                print(canonical_json(result), flush=True)
                if sync_every > 0 and confirmed % sync_every == 0:
                    export_events(conn)
                    subprocess.run([str(SYNC)], check=True, stdin=subprocess.DEVNULL)
            if stage_error is not None:
                raise stage_error
        finally:
            # SQLite commits each object durably. JSONL is a derived snapshot:
            # export at window boundaries, before sync, and on failure. Avoid
            # rewriting the whole event history twice for every small object.
            export_events(conn)
    if results:
        subprocess.run([str(SYNC)], check=True, stdin=subprocess.DEVNULL)
    result = {
        "verdict": "UPLOAD_YIELDED" if yielded is not None else "UPLOAD_PASS",
        "objects": len(results),
        "plain_bytes": sum(int(x["plain_bytes"]) for x in results),
    }
    if yielded is not None:
        result["yield_reason"] = yielded
    return result


def copy_verified(stream: BinaryIO, output: BinaryIO, expected_bytes: int, expected_digest: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(BUF), b""):
        output.write(block)
        digest.update(block)
        size += len(block)
    actual = digest.hexdigest()
    if size != int(expected_bytes) or actual != expected_digest:
        raise VaultRefused(
            f"REFUSE_BAD_PLAINTEXT expected_bytes={expected_bytes} actual_bytes={size} "
            f"expected_sha256={expected_digest} actual_sha256={actual}"
        )
    return size, actual


def decrypt_object(blob: Path, output: Path, expected_bytes: int, expected_digest: str, key_path: Path = KEY) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise VaultRefused(f"REFUSE_RESTORE_PATH_EXISTS path={output}")
    temporary = output.parent / f".{output.name}.{os.getpid()}.partial"
    if temporary.exists():
        raise VaultRefused(f"REFUSE_RESTORE_TEMP_EXISTS path={temporary}")
    process = subprocess.Popen([
        "/usr/local/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
        "--passphrase-file", str(key_path), "--decrypt", str(blob),
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        with temporary.open("wb") as sink:
            copy_verified(process.stdout, sink, expected_bytes, expected_digest)
            sink.flush()
            os.fsync(sink.fileno())
        process.stdout.close()
        detail = process.stderr.read().decode("utf-8", errors="replace")[-2000:]
        process.stderr.close()
        if process.wait() != 0:
            raise VaultRefused(f"REFUSE_GPG_DECRYPT_FAILED detail={detail}")
        os.replace(temporary, output)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        temporary.unlink(missing_ok=True)
        raise


def append_restore_metric(unit_id: str, digest: str, result: dict[str, Any]) -> None:
    path = WS / "logical_vault_v3_restore_metrics.tsv"
    columns = [
        "unit_id", "digest", "started_at", "finished_at", "verdict", "bytes",
        "download_elapsed_s", "download_MBps", "download_MiBps", "task_id",
    ]
    task = result.get("task") or {}
    values = [
        unit_id, digest, result.get("started_at") or "", result.get("finished_at") or "",
        result["verdict"], result["bytes"], result.get("download_elapsed_s", ""),
        result.get("download_MBps", ""), result.get("download_MiBps", ""), task.get("task_id", ""),
    ]
    with path.open("a+", encoding="utf-8", newline="") as output:
        fcntl.flock(output.fileno(), fcntl.LOCK_EX)
        output.seek(0, os.SEEK_END)
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        if output.tell() == 0:
            writer.writerow(["# " + columns[0], *columns[1:]])
        writer.writerow(values)
        output.flush()
        os.fsync(output.fileno())
        fcntl.flock(output.fileno(), fcntl.LOCK_UN)


def restore_unit(
    conn: sqlite3.Connection,
    unit_id: str,
    output_root: Path,
    blob_dir: Path | None,
    download: bool,
    timeout: float,
    purge_downloads: bool,
    key_path: Path = KEY,
) -> dict[str, Any]:
    manifest = assert_manifest(conn, unit_id)
    final = output_root.resolve() / unit_id
    if final.exists():
        raise VaultRefused(f"REFUSE_OUTPUT_EXISTS path={final}")
    output_root.mkdir(parents=True, exist_ok=True)
    entries = list(conn.execute(
        "SELECT ue.logical_path,ue.entry_type,ue.mode,ue.link_target,o.* FROM unit_entries ue "
        "LEFT JOIN objects o USING(digest) WHERE ue.unit_id=? ORDER BY ue.ordinal", (unit_id,),
    ))
    objects = [row for row in entries if row["entry_type"] == "file"]
    if any(row["cloud_state"] != "CLOUD_CONFIRMED" for row in objects):
        raise VaultRefused(f"REFUSE_UNIT_NOT_CLOUD_CONFIRMED unit_id={unit_id}")
    staging = Path(tempfile.mkdtemp(prefix=f".restore-{unit_id.replace('/', '_')}-", dir=output_root))
    safe_unit = re.sub(r"[^A-Za-z0-9_.-]+", "_", unit_id)
    download_root = DOWNLOAD_ROOT / "logical-vault-v3" / safe_unit
    restored_bytes = 0
    try:
        for row in entries:
            relative = safe_relative_path(row["logical_path"])
            destination = staging / relative
            if row["entry_type"] == "directory":
                destination.mkdir(parents=True, exist_ok=False)
                os.chmod(destination, int(row["mode"]))
                continue
            if row["entry_type"] == "symlink":
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(row["link_target"], destination)
                continue
            token_name = PurePosixPath(row["cloud_relpath"]).name
            active_blob_dir = blob_dir or download_root
            blob = active_blob_dir / token_name
            if download:
                try:
                    result = download_cloud_file(
                        f"{CLOUD_BASE}/{row['cloud_relpath']}", active_blob_dir,
                        expected_size=int(row["encrypted_bytes"]),
                        expected_sha256=row["encrypted_sha256"], timeout=timeout,
                    )
                except DownloadRefused as exc:
                    raise VaultRefused(str(exc)) from exc
                append_restore_metric(unit_id, row["digest"], result)
            if not blob.is_file():
                raise VaultRefused(f"REFUSE_BLOB_MISSING path={blob}")
            if blob.stat().st_size != int(row["encrypted_bytes"]) or file_sha256(blob) != row["encrypted_sha256"]:
                raise VaultRefused(f"REFUSE_BAD_CIPHERTEXT digest={row['digest']} path={blob}")
            decrypt_object(blob, destination, row["plain_bytes"], row["digest"], key_path)
            os.chmod(destination, int(row["mode"]))
            restored_bytes += int(row["plain_bytes"])
            if purge_downloads and download:
                blob.unlink(missing_ok=True)
        os.replace(staging, final)
        with conn:
            accessed = time.time()
            conn.execute(
                "UPDATE units SET unit_state='RESTORE_VERIFIED',temperature=CASE WHEN pinned=1 THEN 'PINNED' ELSE 'HOT' END,"
                "local_present=1,last_access=?,lease_until=?,access_count=access_count+1,"
                "access_reason='verified restore',updated_at=? WHERE unit_id=?",
                (accessed, accessed + 8 * 3600, now(), unit_id),
            )
            record_event(conn, "UNIT_RESTORE_VERIFIED", unit_id, {
                "manifest_sha256": manifest_hash(manifest), "objects": len(objects),
                "plain_bytes": restored_bytes, "output": str(final),
            })
        return {
            "verdict": "UNIT_RESTORE_PASS", "unit_id": unit_id,
            "objects": len(objects), "plain_bytes": restored_bytes,
            "manifest_sha256": manifest_hash(manifest), "output": str(final),
        }
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def audit_cloud_inventory(objects: list[sqlite3.Row]) -> int:
    """Match every expected opaque v3 object against Baidu's local cloud index."""
    filecache = _single_account_db("filecache.db")
    with sqlite3.connect(f"file:{filecache}?mode=ro", uri=True) as cloud:
        for row in objects:
            cloud_path = PurePosixPath(f"{CLOUD_BASE}/{row['cloud_relpath']}")
            parent = str(cloud_path.parent).rstrip("/") + "/"
            matches = cloud.execute(
                "SELECT file_size FROM file_meta WHERE parent_path=? AND server_filename=? AND isdir=0",
                (parent, cloud_path.name),
            ).fetchall()
            if len(matches) != 1:
                raise VaultRefused(
                    f"REFUSE_CLOUD_INVENTORY_COUNT digest={row['digest']} count={len(matches)} path={cloud_path}"
                )
            if int(matches[0][0]) != int(row["encrypted_bytes"]):
                raise VaultRefused(
                    f"REFUSE_CLOUD_INVENTORY_SIZE digest={row['digest']} "
                    f"expected={row['encrypted_bytes']} actual={matches[0][0]}"
                )
    return len(objects)


def audit(conn: sqlite3.Connection, batch_id: str | None, require_cloud: bool) -> dict[str, Any]:
    check = conn.execute("PRAGMA quick_check").fetchone()[0]
    if check != "ok":
        raise VaultRefused(f"REFUSE_SQLITE_QUICK_CHECK detail={check}")
    fk = list(conn.execute("PRAGMA foreign_key_check"))
    if fk:
        raise VaultRefused(f"REFUSE_FOREIGN_KEY_CHECK rows={len(fk)}")
    params: list[Any] = []
    clause = ""
    if batch_id:
        clause = " WHERE batch_id=?"
        params.append(batch_id)
    units = list(conn.execute("SELECT * FROM units" + clause + " ORDER BY unit_id", params))
    if not units:
        raise VaultRefused("REFUSE_NO_UNITS_TO_AUDIT")
    for unit in units:
        assert_manifest(conn, unit["unit_id"])
    unit_ids = [row["unit_id"] for row in units]
    placeholders = ",".join("?" for _ in unit_ids)
    objects = list(conn.execute(
        "SELECT DISTINCT o.* FROM objects o JOIN unit_entries ue USING(digest) "
        f"WHERE ue.unit_id IN ({placeholders})", unit_ids,
    ))
    if require_cloud:
        bad = [row for row in objects if row["cloud_state"] != "CLOUD_CONFIRMED" or not row["encrypted_sha256"]]
        if bad:
            raise VaultRefused(f"REFUSE_OBJECTS_NOT_CLOUD_CONFIRMED count={len(bad)}")
        cloud_inventory_objects = audit_cloud_inventory(objects)
    else:
        cloud_inventory_objects = 0
    if batch_id:
        batch = conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if not batch:
            raise VaultRefused(f"REFUSE_UNKNOWN_BATCH batch_id={batch_id}")
        actual_units = len(units)
        actual_bytes = conn.execute(
            "SELECT COALESCE(SUM(o.plain_bytes),0) FROM unit_entries ue JOIN objects o USING(digest) "
            "JOIN units u ON u.unit_id=ue.unit_id WHERE u.batch_id=?",
            (batch_id,),
        ).fetchone()[0]
        if actual_units != batch["expected_units"] or actual_bytes != batch["expected_plain_bytes"]:
            raise VaultRefused(
                f"REFUSE_BATCH_AGGREGATE expected_units={batch['expected_units']} actual_units={actual_units} "
                f"expected_bytes={batch['expected_plain_bytes']} actual_bytes={actual_bytes}"
            )
        if require_cloud:
            with conn:
                conn.execute("UPDATE batches SET batch_state='AUDIT_PASS',updated_at=? WHERE batch_id=?", (now(), batch_id))
    return {
        "verdict": "STRICT_AUDIT_PASS", "batch_id": batch_id,
        "units": len(units), "unique_objects": len(objects),
        "logical_bytes": sum(int(row["plain_bytes"]) for row in objects),
        "require_cloud": require_cloud,
        "cloud_inventory_objects": cloud_inventory_objects,
    }


def status(conn: sqlite3.Connection, batch_id: str | None) -> dict[str, Any]:
    params: list[Any] = []
    unit_filter = ""
    object_filter = ""
    if batch_id:
        unit_filter = " WHERE batch_id=?"
        object_filter = (
            " WHERE EXISTS(SELECT 1 FROM unit_entries ue JOIN units u ON u.unit_id=ue.unit_id "
            "WHERE ue.digest=o.digest AND u.batch_id=?)"
        )
        params = [batch_id]
    unit_rows = list(conn.execute(
        "SELECT unit_state,COUNT(*) count FROM units" + unit_filter + " GROUP BY unit_state",
        params,
    ))
    object_rows = list(conn.execute(
        "SELECT cloud_state,COUNT(*) count,COALESCE(SUM(plain_bytes),0) bytes FROM objects o" + object_filter + " GROUP BY cloud_state",
        params,
    ))
    temperature_rows = list(conn.execute(
        "SELECT temperature,COUNT(*) count FROM units" + unit_filter + " GROUP BY temperature",
        params,
    ))
    return {
        "verdict": "STATUS",
        "batch_id": batch_id,
        "units": {row["unit_state"]: row["count"] for row in unit_rows},
        "temperatures": {row["temperature"]: row["count"] for row in temperature_rows},
        "objects": {row["cloud_state"]: {"count": row["count"], "plain_bytes": row["bytes"]} for row in object_rows},
    }


def touch_unit(
    conn: sqlite3.Connection,
    unit_id: str,
    lease_hours: float,
    reason: str,
) -> dict[str, Any]:
    if lease_hours <= 0 or lease_hours > 24 * 30:
        raise VaultRefused(f"REFUSE_BAD_LEASE_HOURS value={lease_hours}")
    row = conn.execute("SELECT * FROM units WHERE unit_id=?", (unit_id,)).fetchone()
    if not row:
        raise VaultRefused(f"REFUSE_UNKNOWN_UNIT unit_id={unit_id}")
    accessed = time.time()
    temperature = "PINNED" if row["pinned"] else "HOT"
    with conn:
        conn.execute(
            "UPDATE units SET temperature=?,last_access=?,lease_until=?,access_count=access_count+1,"
            "access_reason=?,updated_at=? WHERE unit_id=?",
            (temperature, accessed, accessed + lease_hours * 3600, reason, now(), unit_id),
        )
        record_event(conn, "UNIT_TOUCHED", unit_id, {
            "temperature": temperature, "lease_hours": lease_hours, "reason": reason,
        })
    return {
        "verdict": "UNIT_TOUCH_PASS", "unit_id": unit_id,
        "temperature": temperature, "lease_until": accessed + lease_hours * 3600,
    }


def temperature_plan(
    conn: sqlite3.Connection,
    hot_days: float,
    cold_days: float,
    apply: bool,
) -> dict[str, Any]:
    if hot_days < 0 or cold_days <= hot_days:
        raise VaultRefused(f"REFUSE_BAD_TEMPERATURE_POLICY hot_days={hot_days} cold_days={cold_days}")
    current = time.time()
    transitions = []
    counts: dict[str, int] = {}
    for row in conn.execute("SELECT unit_id,pinned,temperature,last_access,lease_until FROM units"):
        last_access = current if row["last_access"] is None else float(row["last_access"])
        age_days = (current - last_access) / 86400
        if row["pinned"]:
            desired = "PINNED"
        elif row["lease_until"] and float(row["lease_until"]) > current:
            desired = "HOT"
        elif age_days < hot_days:
            desired = "HOT"
        elif age_days < cold_days:
            desired = "WARM"
        else:
            desired = "COLD"
        counts[desired] = counts.get(desired, 0) + 1
        if desired != row["temperature"]:
            transitions.append((desired, now(), row["unit_id"]))
    if apply and transitions:
        with conn:
            conn.executemany(
                "UPDATE units SET temperature=?,updated_at=? WHERE unit_id=?", transitions,
            )
            record_event(conn, "TEMPERATURE_PLAN_APPLIED", "all", {
                "hot_days": hot_days, "cold_days": cold_days,
                "transitions": len(transitions), "counts": counts,
            })
    return {
        "verdict": "TEMPERATURE_PLAN", "apply": apply,
        "hot_days": hot_days, "cold_days": cold_days,
        "transitions": len(transitions), "counts": counts,
    }


def eviction_candidates(conn: sqlite3.Connection, limit: int) -> dict[str, Any]:
    if limit < 1 or limit > 10000:
        raise VaultRefused(f"REFUSE_BAD_CANDIDATE_LIMIT value={limit}")
    current = time.time()
    rows = [dict(row) for row in conn.execute(
        "SELECT u.unit_id,u.batch_id,u.name,u.last_access,u.access_count,o.digest,o.plain_bytes,"
        "s.host,s.source_path FROM units u JOIN unit_entries e USING(unit_id) "
        "JOIN objects o USING(digest) JOIN object_sources s USING(digest) "
        "LEFT JOIN batches b USING(batch_id) WHERE u.kind='tool_capsule' AND u.temperature='COLD' "
        "AND u.pinned=0 AND (u.lease_until IS NULL OR u.lease_until<=?) "
        "AND u.unit_state IN ('CLOUD_CONFIRMED','RESTORE_VERIFIED') "
        "AND o.cloud_state='CLOUD_CONFIRMED' AND s.source_state='HASH_VERIFIED' "
        "AND (u.batch_id IS NULL OR b.batch_state='AUDIT_PASS') "
        "ORDER BY COALESCE(u.last_access,0),o.plain_bytes DESC,u.unit_id LIMIT ?",
        (current, limit),
    )]
    return {
        "verdict": "EVICTION_CANDIDATES", "count": len(rows),
        "logical_bytes": sum(int(row["plain_bytes"]) for row in rows),
        "candidates": rows,
        "deletion_authorized": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")

    register_batch = sub.add_parser("register-function-batch")
    register_batch.add_argument("--batch-id", required=True)
    register_batch.add_argument("--mapping", type=Path, required=True)
    register_batch.add_argument("--source-root", required=True)
    register_batch.add_argument("--source-host", default=REMOTE_hostb)

    register_directory = sub.add_parser("register-tree")
    register_directory.add_argument("--unit-id", required=True)
    register_directory.add_argument("--kind", choices=sorted(KINDS - {"tool_capsule"}), required=True)
    register_directory.add_argument("--source-root", type=Path, required=True)
    register_directory.add_argument("--snapshot-proof", type=Path)
    register_directory.add_argument("--name")

    plan = sub.add_parser("plan-upload")
    plan.add_argument("--batch")
    plan.add_argument("--unit")
    plan.add_argument("--limit", type=int)

    upload = sub.add_parser("upload")
    upload.add_argument("--batch")
    upload.add_argument("--unit")
    upload.add_argument("--limit", type=int)
    upload.add_argument("--sync-every", type=int, default=25)
    upload.add_argument("--window", type=int, default=8)
    # 64MiB, not 4GiB: a window is staged into the Baidu backup folder at once, and
    # the client's watcher loses create events for large files landing together
    # (<date>: 3x178MB in one window -> 11.7x slower, third never registered).
    # Tiny tool capsules still batch; anything big gets its own window.
    upload.add_argument("--max-window-bytes", type=int, default=64 * 1024 * 1024)

    restore = sub.add_parser("restore")
    restore.add_argument("--unit", required=True)
    restore.add_argument("--output-root", type=Path, required=True)
    restore.add_argument("--blob-dir", type=Path)
    restore.add_argument("--download", action="store_true")
    restore.add_argument("--download-timeout", type=float, default=1800)
    restore.add_argument("--purge-downloaded", action="store_true")

    verify = sub.add_parser("verify-batch")
    verify.add_argument("--batch", required=True)
    verify.add_argument("--require-cloud", action="store_true")

    strict = sub.add_parser("strict-audit")
    strict.add_argument("--batch")
    strict.add_argument("--require-cloud", action="store_true")

    show = sub.add_parser("status")
    show.add_argument("--batch")

    touch = sub.add_parser("touch")
    touch.add_argument("--unit", required=True)
    touch.add_argument("--lease-hours", type=float, default=8)
    touch.add_argument("--reason", default="logical access")

    temperatures = sub.add_parser("temperature-plan")
    temperatures.add_argument("--hot-days", type=float, default=3)
    temperatures.add_argument("--cold-days", type=float, default=15)
    temperatures.add_argument("--apply", action="store_true")

    candidates = sub.add_parser("eviction-candidates")
    candidates.add_argument("--limit", type=int, default=100)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        key_bytes = read_key()
        with connect(args.db) as conn:
            init_db(conn)
            if args.command == "init":
                result = {"verdict": "INIT_PASS", "db": str(args.db), "schema_version": SCHEMA_VERSION}
            elif args.command == "register-function-batch":
                with writer_lock():
                    result = register_function_batch(
                        conn, key_bytes, args.batch_id, args.mapping,
                        args.source_root, args.source_host,
                    )
            elif args.command == "register-tree":
                with writer_lock():
                    result = register_tree(
                        conn, key_bytes, args.unit_id, args.kind, args.source_root,
                        args.snapshot_proof, args.name,
                    )
            elif args.command == "plan-upload":
                rows = select_objects(conn, args.batch, args.unit, args.limit)
                result = {
                    "verdict": "UPLOAD_PLAN", "objects": len(rows),
                    "plain_bytes": sum(int(row["plain_bytes"]) for row in rows),
                    "min_object_bytes": min((row["plain_bytes"] for row in rows), default=0),
                    "max_object_bytes": max((row["plain_bytes"] for row in rows), default=0),
                    "granularity": "natural_file",
                }
            elif args.command == "upload":
                with writer_lock():
                    result = run_upload(
                        conn, args.batch, args.unit, args.limit, args.sync_every,
                        args.window, args.max_window_bytes,
                    )
            elif args.command == "restore":
                if args.blob_dir and args.download:
                    raise VaultRefused("REFUSE_BLOB_DIR_WITH_DOWNLOAD")
                if not args.blob_dir and not args.download:
                    raise VaultRefused("REFUSE_RESTORE_WITHOUT_BLOB_SOURCE")
                with writer_lock():
                    result = restore_unit(
                        conn, args.unit, args.output_root, args.blob_dir, args.download,
                        args.download_timeout, args.purge_downloaded,
                    )
            elif args.command in ("verify-batch", "strict-audit"):
                with writer_lock():
                    result = audit(conn, getattr(args, "batch", None), args.require_cloud)
            elif args.command == "status":
                result = status(conn, args.batch)
            elif args.command == "touch":
                with writer_lock():
                    result = touch_unit(conn, args.unit, args.lease_hours, args.reason)
            elif args.command == "temperature-plan":
                with writer_lock():
                    result = temperature_plan(
                        conn, args.hot_days, args.cold_days, args.apply,
                    )
            elif args.command == "eviction-candidates":
                result = eviction_candidates(conn, args.limit)
            else:
                raise AssertionError(args.command)
            export_events(conn)
        print(canonical_json(result))
        return 0
    except (VaultRefused, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
