#!/usr/bin/env python3
"""Fail-closed physical-pool migration executor for the hostb host.

Run on hostb as user.  `copy` performs an online first rsync pass.  `cutover`
stops only the declared services, performs the second pass, proves a content
fingerprint match, switches either a bind mount or a logical path atomically,
smoke-checks services, and only then removes the old bytes.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "workspace_pool_migration_manifest.json"
STATE = Path.home() / ".coldstore/state/workspace_pool_migration.jsonl"
LOCK = Path.home() / ".coldstore/state/workspace_pool_migration.lock"
FINGERPRINT = Path.home() / ".coldstore/bin/workspace_archive_remote.py"
MIN_HEADROOM = 5 * 1024**3


class MigrationRefused(RuntimeError):
    pass


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run(args, *, capture=False, check=True):
    result = subprocess.run(
        args, stdin=subprocess.DEVNULL, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if check and result.returncode:
        detail = (result.stdout or "")[-3000:]
        raise MigrationRefused(
            f"REFUSE_COMMAND_FAILED rc={result.returncode} command={args[0]} detail={detail}"
        )
    return result


def normalized_absolute(path):
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    pure = PurePosixPath(path)
    return str(pure) == path and ".." not in pure.parts and path != "/"


def validate_item(item):
    required = {"id", "mode", "source", "target", "services"}
    if not required <= set(item):
        raise MigrationRefused(f"REFUSE_MANIFEST_FIELDS id={item.get('id')}")
    if item["mode"] not in {"bind", "move"}:
        raise MigrationRefused(f"REFUSE_MANIFEST_MODE id={item['id']}")
    if not normalized_absolute(item["source"]) or not normalized_absolute(item["target"]):
        raise MigrationRefused(f"REFUSE_MANIFEST_PATH id={item['id']}")
    if item["mode"] == "bind":
        if not item["target"].startswith("/data/isolation/"):
            raise MigrationRefused(f"REFUSE_BIND_TARGET id={item['id']}")
        if not item["source"].startswith(("/home/user/", "/var/lib/local-llm")):
            raise MigrationRefused(f"REFUSE_BIND_SOURCE id={item['id']}")
    else:
        allowed_move_source = (
            item["source"].startswith("/data/relocated/")
            or item["source"].startswith("/data/asset-pool-v3/")
            or item["source"] in {
                "/data/asset-pool", "/data/live-service",
            }
        )
        if not allowed_move_source:
            raise MigrationRefused(f"REFUSE_MOVE_SOURCE id={item['id']}")
        if not item["target"].startswith("/home/user/"):
            raise MigrationRefused(f"REFUSE_MOVE_TARGET id={item['id']}")
    for service in item["services"]:
        if service.get("scope") not in {"system", "user"} or not service.get("name"):
            raise MigrationRefused(f"REFUSE_SERVICE_SPEC id={item['id']}")
    return item


def load_manifest(path):
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationRefused(f"REFUSE_MANIFEST_UNREADABLE {path}") from exc
    if doc.get("schema_version") != 1:
        raise MigrationRefused("REFUSE_MANIFEST_SCHEMA")
    items = {}
    for row in doc.get("physical_moves", []):
        item = validate_item(row)
        if item["id"] in items:
            raise MigrationRefused(f"REFUSE_DUPLICATE_ITEM {item['id']}")
        items[item["id"]] = item
    return doc, items


def receipt(event, item, **extra):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    row = {"at": now_iso(), "event": event, "id": item["id"],
           "source": item["source"], "target": item["target"], **extra}
    with STATE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return row


def sudo(*args, capture=False, check=True):
    return run(["sudo", "-n", *map(str, args)], capture=capture, check=check)


def path_size(path):
    result = sudo("du", "-sb", "--", path, capture=True)
    try:
        return int(result.stdout.split()[0])
    except (ValueError, IndexError) as exc:
        raise MigrationRefused(f"REFUSE_SIZE_PARSE path={path}") from exc


def fingerprint(path):
    encoded = base64.b64encode(path.encode("utf-8")).decode("ascii")
    result = sudo(FINGERPRINT, "content-fingerprint", "--path-b64", encoded,
                  capture=True)
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise MigrationRefused(f"REFUSE_FINGERPRINT_PARSE path={path}") from exc
    if len(str(value.get("sha256") or "")) != 64:
        raise MigrationRefused(f"REFUSE_FINGERPRINT_INVALID path={path}")
    return value


def stage_path(item):
    return item["target"] if item["mode"] == "bind" else item["target"] + ".pool-stage"


def free_bytes(path):
    parent = Path(path).parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return shutil.disk_usage(parent).free


def rsync(source, target, *, delete=False):
    sudo("mkdir", "-p", "--", target)
    command = ["rsync", "-aHAXS", "--numeric-ids", "--one-file-system"]
    if delete:
        command.append("--delete")
    command.extend([source.rstrip("/") + "/", target.rstrip("/") + "/"])
    sudo(*command)


def copy_pass(item):
    source, target = item["source"], stage_path(item)
    if not Path(source).is_dir() or Path(source).is_symlink():
        raise MigrationRefused(f"REFUSE_SOURCE_NOT_REAL_DIRECTORY {source}")
    size = path_size(source)
    if not Path(target).exists() and free_bytes(target) < size + MIN_HEADROOM:
        raise MigrationRefused(
            f"REFUSE_TARGET_HEADROOM need={size + MIN_HEADROOM} free={free_bytes(target)}"
        )
    rsync(source, target, delete=False)
    row = receipt("COPY_PASS", item, bytes=size)
    print(json.dumps(row, ensure_ascii=False, sort_keys=True))


def service_command(service, action, *, check=True):
    if service["scope"] == "system":
        return sudo("systemctl", action, service["name"], check=check)
    return run(["systemctl", "--user", action, service["name"]], check=check)


def service_active(service):
    return service_command(service, "is-active", check=False).returncode == 0


def open_handles(path):
    result = sudo("lsof", "-Fn", "+D", path, capture=True, check=False)
    return [line for line in (result.stdout or "").splitlines()
            if line.startswith(("p", "f", "n"))]


def update_fstab_bind(source, target, item_id):
    marker = f"# workspace-pool:{item_id}"
    line = f"{target} {source} none bind,nofail,x-systemd.requires-mounts-for=/data 0 0 {marker}"
    current = sudo("cat", "/etc/fstab", capture=True).stdout
    existing = [row for row in current.splitlines() if marker in row]
    if existing and existing != [line]:
        raise MigrationRefused(f"REFUSE_FSTAB_MARKER_CONFLICT id={item_id}")
    if existing:
        return None
    backup = f"/etc/fstab.pre-workspace-pool-{item_id}-{int(time.time())}"
    sudo("cp", "--", "/etc/fstab", backup)
    tmp = Path(f"/tmp/fstab.workspace-pool.{os.getpid()}")
    tmp.write_text(current.rstrip("\n") + "\n" + line + "\n", encoding="utf-8")
    try:
        sudo("install", "-m", "644", "--", tmp, "/etc/fstab")
    finally:
        tmp.unlink(missing_ok=True)
    return backup


def remove_fstab_marker(item_id):
    marker = f"# workspace-pool:{item_id}"
    current = sudo("cat", "/etc/fstab", capture=True).stdout
    filtered = "\n".join(row for row in current.splitlines() if marker not in row) + "\n"
    tmp = Path(f"/tmp/fstab.workspace-pool.rollback.{os.getpid()}")
    tmp.write_text(filtered, encoding="utf-8")
    try:
        sudo("install", "-m", "644", "--", tmp, "/etc/fstab")
    finally:
        tmp.unlink(missing_ok=True)


def smoke_services(services):
    failed = [service["name"] for service in services
              if not service_active(service)]
    if failed:
        raise MigrationRefused(f"REFUSE_SERVICE_SMOKE_FAILED services={failed}")


def verify_bind_mapping(source, target, expected_sha256=None):
    try:
        same_directory = os.path.samefile(source, target)
    except OSError:
        same_directory = False
    if not same_directory:
        raise MigrationRefused("REFUSE_BIND_VISIBLE_IDENTITY_MISMATCH")
    if expected_sha256 is None:
        return
    visible = fingerprint(source)
    if visible["sha256"] != expected_sha256:
        raise MigrationRefused("REFUSE_BIND_VISIBLE_FINGERPRINT_MISMATCH")


def cutover_bind(item, active):
    source, target = item["source"], item["target"]
    before = fingerprint(source)
    rsync(source, target, delete=True)
    after = fingerprint(target)
    if before["sha256"] != after["sha256"] or before.get("bytes") != after.get("bytes"):
        raise MigrationRefused("REFUSE_SECOND_PASS_FINGERPRINT_MISMATCH")
    stat = Path(source).stat()
    backup = source + f".pool-old-{int(time.time())}"
    fstab_backup = None
    try:
        sudo("mv", "--", source, backup)
        sudo("install", "-d", "-m", format(stat.st_mode & 0o7777, "o"),
             "-o", str(stat.st_uid), "-g", str(stat.st_gid), "--", source)
        sudo("mount", "--bind", target, source)
        fstab_backup = update_fstab_bind(source, target, item["id"])
        mounted = sudo("findmnt", "-rn", "-T", source, "-o", "TARGET,SOURCE",
                       capture=True).stdout.strip()
        if not mounted.startswith(source + " "):
            raise MigrationRefused(f"REFUSE_BIND_MOUNT_NOT_ACTIVE output={mounted}")
        # Prove byte identity while writers are still stopped.  Once mutable
        # services restart, comparing against the pre-start fingerprint would
        # reject legitimate writes and spuriously roll the migration back.
        verify_bind_mapping(source, target, after["sha256"])
        for service in active:
            service_command(service, "start")
        smoke_services(active)
        # The bind root must still be the exact target inode after services
        # restart; this proof is stable even when those services write data.
        verify_bind_mapping(source, target)
        sudo("rm", "-rf", "--", backup)
        return before
    except BaseException:
        for service in active:
            service_command(service, "stop", check=False)
        sudo("umount", source, check=False)
        remove_fstab_marker(item["id"])
        sudo("rmdir", "--", source, check=False)
        if Path(backup).exists() and not Path(source).exists():
            sudo("mv", "--", backup, source)
        for service in active:
            service_command(service, "start", check=False)
        raise


def cutover_move(item, active):
    source, target, stage = item["source"], item["target"], stage_path(item)
    link_target = os.readlink(target) if os.path.islink(target) else None
    if link_target is not None and link_target != source:
        raise MigrationRefused("REFUSE_LOGICAL_SYMLINK_MISMATCH")
    if link_target is None and os.path.lexists(target):
        raise MigrationRefused("REFUSE_LOGICAL_TARGET_OCCUPIED")
    before = fingerprint(source)
    rsync(source, stage, delete=True)
    after = fingerprint(stage)
    if before["sha256"] != after["sha256"] or before.get("bytes") != after.get("bytes"):
        raise MigrationRefused("REFUSE_SECOND_PASS_FINGERPRINT_MISMATCH")
    if link_target is not None:
        os.unlink(target)
    os.replace(stage, target)
    try:
        for service in active:
            service_command(service, "start")
        smoke_services(active)
        visible = fingerprint(target)
        if visible["sha256"] != after["sha256"]:
            raise MigrationRefused("REFUSE_MOVE_VISIBLE_FINGERPRINT_MISMATCH")
        sudo("rm", "-rf", "--", source)
        return before
    except BaseException:
        for service in active:
            service_command(service, "stop", check=False)
        if not os.path.lexists(stage) and os.path.exists(target):
            os.replace(target, stage)
        if link_target is not None and not os.path.lexists(target):
            os.symlink(source, target)
        for service in active:
            service_command(service, "start", check=False)
        raise


def cutover(item):
    stage = stage_path(item)
    if not Path(item["source"]).is_dir() or not Path(stage).is_dir():
        raise MigrationRefused("REFUSE_COPY_PASS_MISSING")
    active = [service for service in item["services"] if service_active(service)]
    for service in reversed(active):
        service_command(service, "stop")
    try:
        handles = open_handles(item["source"])
        if handles:
            raise MigrationRefused("REFUSE_SOURCE_OPEN_HANDLES " + " ".join(handles[:30]))
        result = (cutover_bind(item, active) if item["mode"] == "bind"
                  else cutover_move(item, active))
    except BaseException:
        for service in active:
            if not service_active(service):
                service_command(service, "start", check=False)
        raise
    row = receipt("CUTOVER_PASS", item, content_fingerprint=result["sha256"],
                  bytes=result.get("bytes"), services=[x["name"] for x in active])
    print(json.dumps(row, ensure_ascii=False, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    for name in ("copy", "cutover"):
        command = sub.add_parser(name)
        command.add_argument("item_id")
        command.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    doc, items = load_manifest(args.manifest)
    if args.command == "plan":
        print(json.dumps({
            "schema_version": doc["schema_version"],
            "items": list(items.values()),
        }, ensure_ascii=False, sort_keys=True, indent=2))
        return
    if not args.execute:
        raise MigrationRefused("REFUSE_EXECUTE_FLAG_REQUIRED")
    item = items.get(args.item_id)
    if not item:
        raise MigrationRefused(f"REFUSE_UNKNOWN_ITEM {args.item_id}")
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MigrationRefused("REFUSE_POOL_MIGRATION_BUSY") from exc
        if args.command == "copy":
            copy_pass(item)
        else:
            cutover(item)


if __name__ == "__main__":
    try:
        main()
    except MigrationRefused as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
