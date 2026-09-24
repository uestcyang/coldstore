#!/usr/bin/env python3
"""Narrow hostb-side helper for the Mac Workspace archiver."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from workspace_consistency import ConsistencyRefused, inspect_workspace
from workspace_pager import content_fingerprint


def decode(value):
    return os.fsdecode(base64.b64decode(value))


def snapshot(path):
    if not os.path.exists(path) or os.path.islink(path):
        raise SystemExit("REFUSE_MISSING_OR_SYMLINK_ROOT")
    h = hashlib.sha256(); count = total = 0

    def add(full, rel):
        nonlocal count, total
        st = os.lstat(full)
        if os.path.islink(full): kind, extra = "l", os.readlink(full)
        elif os.path.isdir(full): kind, extra = "d", ""
        elif os.path.isfile(full): kind, extra = "f", ""; total += st.st_size
        else: kind, extra = "o", ""
        row = [rel, kind, st.st_mode, st.st_size, st.st_mtime_ns, extra]
        h.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
        h.update(b"\n"); count += 1

    if os.path.isfile(path):
        add(path, os.path.basename(path))
    else:
        add(path, ".")
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
            dirs.sort(); files.sort()
            for name in dirs + files:
                full = os.path.join(root, name)
                add(full, os.path.relpath(full, path))
    print(json.dumps({"sha256": h.hexdigest(), "entries": count, "bytes": total},
                     sort_keys=True))


def open_fds(path):
    prefix = path.rstrip("/") + "/"; hits = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        root = "/proc/" + pid + "/fd"
        try: names = os.listdir(root)
        except OSError: continue
        for fd in names:
            try: target = os.path.realpath(root + "/" + fd)
            except OSError: continue
            if target == path or target.startswith(prefix):
                hits.append(pid + ":" + fd + ":" + target)
            if len(hits) >= 20: break
        if len(hits) >= 20: break
    print(json.dumps(hits, ensure_ascii=False))


def running_refs(path):
    from pathlib import Path
    hits = []
    running = Path("/home/user/.coldstore/dispatch/running")
    if running.is_dir():
        for job in running.iterdir():
            text = ""
            for name in ("task.json", "prompt.md"):
                try: text += (job / name).read_text(errors="replace") + "\n"
                except OSError: pass
            if path in text: hits.append(job.name)
    print(json.dumps(hits))


def process_refs(path, proc_root=Path('/proc'), own_pid=None):
    """Only return PID/kind; never emit argv, maps, environment or user data.

    Python closes its .py after loading it, so lsof alone cannot protect a
    running service's restart dependency. Called immediately before eviction.
    """
    target = os.path.normpath(path)
    if not target.startswith('/') or target == '/':
        raise ConsistencyRefused('REFUSE_PROCESS_REFERENCE_TARGET')
    own_pid = os.getpid() if own_pid is None else own_pid
    hits, checked = [], 0
    deadline = time.monotonic() + 30

    def within(value, cwd='/'):
        value = value.removesuffix(' (deleted)')
        if '=' in value and value.startswith('-'):
            value = value.split('=', 1)[1]
        if not value or value.startswith('-'):
            return False
        full = os.path.normpath(value if value.startswith('/') else os.path.join(cwd, value))
        return full == target or full.startswith(target + '/')

    try:
        processes = list(proc_root.iterdir())
    except OSError as exc:
        raise ConsistencyRefused('REFUSE_PROCESS_REFERENCE_SCAN') from exc
    for root in processes:
        if not root.name.isdigit() or int(root.name) == own_pid:
            continue
        if time.monotonic() > deadline:
            raise ConsistencyRefused('REFUSE_PROCESS_REFERENCE_TIMEOUT')
        try:
            args = root.joinpath('cmdline').read_bytes().split(b'\0')
            if not any(args):  # kernel thread or already reaped process
                continue
            cwd = os.readlink(root / 'cwd')
            executable = os.readlink(root / 'exe')
            kinds = set()
            if within(cwd): kinds.add('cwd')
            if within(executable): kinds.add('executable')
            if any(within(os.fsdecode(arg), cwd) for arg in args): kinds.add('argv_path')
            for line in root.joinpath('maps').read_text().splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and within(fields[5]): kinds.add('mapped_file')
            checked += 1
            if kinds: hits.append({'pid': int(root.name), 'kinds': sorted(kinds)})
        except FileNotFoundError as exc:
            if root.exists():
                raise ConsistencyRefused('REFUSE_PROCESS_REFERENCE_RACE') from exc
        except (OSError, UnicodeError) as exc:
            raise ConsistencyRefused('REFUSE_PROCESS_REFERENCE_SCAN') from exc
    return {'schema': 'workspace-process-refs/v1', 'checked': checked, 'hits': hits}


def tar_stream(path):
    parent, base = os.path.dirname(path), os.path.basename(path)
    os.execvp("tar", ["tar", "--sort=name", "--numeric-owner", "--acls", "--xattrs",
                      "--sparse", "--pax-option=delete=atime,delete=ctime", "-C", parent,
                      "-cf", "-", "--", base])


def print_content_fingerprint(path):
    if not os.path.exists(path) or os.path.islink(path):
        raise SystemExit("REFUSE_MISSING_OR_SYMLINK_ROOT")
    print(json.dumps(content_fingerprint(path), ensure_ascii=False, sort_keys=True))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("snapshot", "content-fingerprint", "consistency",
                                       "open-fds", "running-refs", "process-refs", "tar"))
    ap.add_argument("--path-b64", required=True)
    args = ap.parse_args(); path = decode(args.path_b64)
    if args.action == "snapshot": snapshot(path)
    elif args.action == "content-fingerprint": print_content_fingerprint(path)
    elif args.action == "consistency":
        print(json.dumps(inspect_workspace(path), ensure_ascii=False, sort_keys=True))
    elif args.action == "open-fds": open_fds(path)
    elif args.action == "running-refs": running_refs(path)
    elif args.action == "process-refs": print(json.dumps(process_refs(path)))
    else: tar_stream(path)


if __name__ == "__main__":
    try:
        main()
    except ConsistencyRefused as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
