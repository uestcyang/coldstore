#!/usr/bin/env python3
"""Build and verify immutable file selections for mixed hot/cold roots."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path

BUF = 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(BUF), b""):
            h.update(block)
    return h.hexdigest()


def selected(base, cutoff, excludes):
    rows = []
    for root, dirs, files in os.walk(base):
        dirs.sort()
        files.sort()
        for name in files:
            path = Path(root) / name
            rel = str(path.relative_to(base))
            marker = "/" + rel
            if any(x in marker for x in excludes):
                continue
            try:
                st = path.stat(follow_symlinks=False)
            except OSError:
                continue
            if not path.is_file() or st.st_mtime > cutoff:
                continue
            if "\x00" in rel:
                raise SystemExit(f"REFUSE_NUL_NAME {rel!r}")
            rows.append((rel, st.st_size, st.st_mtime_ns))
    return rows


def build(args):
    base = Path(args.base).resolve()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = selected(base, args.cutoff_epoch, args.exclude)
    files0 = out / f"{args.label}.files0.gz"
    search = out / f"{args.label}.jsonl.gz"
    with gzip.open(files0, "wb", compresslevel=9) as f0, gzip.open(search, "wt", encoding="utf-8", compresslevel=9) as js:
        for rel, size, mtime_ns in rows:
            f0.write(os.fsencode(rel) + b"\0")
            js.write(json.dumps({"asset_id": args.label, "relative_path": rel, "size": size,
                                 "mtime_ns": mtime_ns}, ensure_ascii=False, sort_keys=True) + "\n")
    total = sum(r[1] for r in rows)
    print(json.dumps({"label": args.label, "base": str(base), "cutoff_epoch": args.cutoff_epoch,
                      "files": len(rows), "bytes": total, "files0": str(files0),
                      "files0_sha256": digest(files0), "search": str(search),
                      "search_sha256": digest(search), "excludes": args.exclude}, ensure_ascii=False))


def verify(args):
    base = Path(args.base).resolve()
    manifest = Path(args.files0).resolve()
    if digest(manifest) != args.manifest_sha256:
        raise SystemExit("REFUSE_MANIFEST_SHA_MISMATCH")
    search = Path(args.search).resolve()
    if digest(search) != args.search_sha256:
        raise SystemExit("REFUSE_SEARCH_MANIFEST_SHA_MISMATCH")
    expected = {}
    with gzip.open(search, "rt", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            expected[row["relative_path"]] = (row["size"], row["mtime_ns"])
    with gzip.open(manifest, "rb") as f:
        names = f.read().split(b"\0")
    if names and names[-1] == b"":
        names.pop()
    count = 0
    total = 0
    for raw in names:
        rel = os.fsdecode(raw)
        path = base / rel
        try:
            st = path.stat(follow_symlinks=False)
        except OSError as e:
            raise SystemExit(f"REFUSE_MISSING {rel}: {e}")
        if not path.is_file():
            raise SystemExit(f"REFUSE_NOT_FILE {rel}")
        saved = expected.get(rel)
        if saved is None or saved != (st.st_size, st.st_mtime_ns):
            raise SystemExit(f"REFUSE_FILE_DRIFT {rel}")
        count += 1
        total += st.st_size
    if count != args.expected_files or total != args.expected_bytes:
        raise SystemExit(f"REFUSE_SELECTION_DRIFT files={count}/{args.expected_files} bytes={total}/{args.expected_bytes}")
    print(f"MANIFEST_VERIFY_PASS files={count} bytes={total} sha256={args.manifest_sha256}")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="command", required=True)
    b = sp.add_parser("build")
    b.add_argument("--label", required=True)
    b.add_argument("--base", required=True)
    b.add_argument("--cutoff-epoch", required=True, type=float)
    b.add_argument("--output", required=True)
    b.add_argument("--exclude", action="append", default=[])
    b.set_defaults(func=build)
    v = sp.add_parser("verify")
    v.add_argument("--base", required=True)
    v.add_argument("--files0", required=True)
    v.add_argument("--manifest-sha256", required=True)
    v.add_argument("--search", required=True)
    v.add_argument("--search-sha256", required=True)
    v.add_argument("--expected-files", required=True, type=int)
    v.add_argument("--expected-bytes", required=True, type=int)
    v.set_defaults(func=verify)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
