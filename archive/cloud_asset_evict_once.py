#!/usr/bin/env python3
"""Watermark-driven warm-page eviction -- trust-the-cloud contract (<date>).

Operator policy "trust-the-cloud".  Nothing is ever downloaded
back from Baidu to earn the right to delete a local copy.  The proof that a page may
be evicted is entirely local + ledger-based:

  * the current archive head of the asset is cloud-confirmed (vault ledger / catalog);
  * the archive head covers the *whole* page root (a frozen-subset ``manifest://``
    head can never authorise deleting the root it was cut from);
  * the local tree still equals the snapshot the archiver took when that head was
    uploaded -- metadata snapshot (path/mode/size/mtime of every entry) for pages
    archived by workspace_archive.py, content fingerprint for legacy assets whose
    only proof is a historical restore test;
  * the per-version file manifest exists and the catalogue + manifests are
    replicated to hostb and iCloud (three-copy metadata, so a deleted tree can
    always be *described*);
  * the delete preflight passes, no open handles, root resolves to itself, and
    neither the head nor the local snapshot changed between proof and ``rm``.

A local tree that drifted from its archived snapshot is marked dirty on the pager
(-> REARCHIVE_REQUIRED) and refused; it is re-uploaded, never silently deleted.
"""
import argparse
import base64
import csv
import fcntl
import hashlib
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
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath

WS = Path(__file__).resolve().parent
def _coldstore_bin() -> Path:
    env = os.environ.get("COLDSTORE_BIN")
    if env:
        return Path(env).expanduser()
    user = Path.home() / ".coldstore/bin"
    if (user / "ws").exists():
        return user
    return Path(__file__).resolve().parent.parent / "pager"  # in-repo sibling layout


COLDSTORE_BIN = _coldstore_bin()
sys.path.insert(0, str(COLDSTORE_BIN))
import workspace_pager as pager  # noqa: E402
REMOTE = os.environ.get("COLDSTORE_REMOTE", "user@host-b")
REMOTE_META = "/home/user/.coldstore/archive"
REMOTE_HELPER = "/home/user/.coldstore/bin/workspace_archive_remote.py"
ICLOUD = Path(os.environ.get('COLDSTORE_ICLOUD_DIR', '~/Library/Mobile Documents/com~apple~CloudDocs/coldstore-recovery')).expanduser()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# workspace_snapshot_proofs.tsv reason tags that count as "what the local tree
# looked like when the current cloud copy was made".  Column 4 is the metadata
# snapshot sha (workspace_archive.py) or the content fingerprint (legacy restore
# test); column 8 says which comparator applies.
ARCHIVE_PROOF_METADATA = "pre_post_metadata_equal"
ARCHIVE_PROOF_CONTENT = "baidu_native_download_decrypt_tar_source_match"
VERSION_MANIFESTS = "cloud_asset_version_manifests.tsv"
# Deployment-specific source roots that may be evicted; ship as config, not code.
_ALLOWED_DEFAULT = ("/home/user/project-a/", "/home/user/archive/", "/home/user/asset-pool-v3/", "/data/asset-pool-v3/")
ALLOWED_PREFIXES = tuple(
    p if p.endswith("/") else p + "/"
    for p in (os.environ.get("COLDSTORE_ALLOWED_PREFIXES", "").split(":") if os.environ.get("COLDSTORE_ALLOWED_PREFIXES") else _ALLOWED_DEFAULT)
    if p)
MIGRATION_MANIFEST = WS / "workspace_pool_migration_manifest.json"
VERSION_HEADS = WS / "vault_v2_heads.json"


def migration_entries(path=None, *, require_fingerprint=True):
    path = MIGRATION_MANIFEST if path is None else Path(path)
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if doc.get("schema_version") != 1:
        return {}
    return {
        str(row.get("asset_id")): row
        for row in doc.get("entries", [])
        if (row.get("approved") is True
            and row.get("asset_id")
            and row.get("source")
            and row.get("target_path")
            and row.get("disposition") == "EVICT_TO_COLD"
            and (not require_fingerprint
                 or len(str(row.get("expected_content_fingerprint") or "")) == 64))
    }


def migration_target_allowed(path):
    if not isinstance(path, str) or not path.startswith("/home/user/"):
        return False
    normalized = str(PurePosixPath(path))
    return normalized == path and ".." not in PurePosixPath(path).parts


def registered_workspace_allowed(source, asset_id, *, page_rows=None, heads=None, now=None):
    """Exact public workspace identity, not a broad /home permission expansion.

    The original executor only knew four legacy roots, so newly snapshotted
    workspaces were uploaded but could never enter its source-match verifier.
    A registered WARM page may use the same verifier; ALL subsequent restore,
    hash, current-version, redundancy, open-handle and delete gates still apply.
    """
    if not str(asset_id or '').startswith('ws-hostb-'):
        return False
    path = PurePosixPath(source)
    if (not source.startswith('/home/user/') or str(path) != source
            or '..' in path.parts or any(p.startswith('.') for p in path.parts)
            or source in {p.rstrip('/') for p in ALLOWED_PREFIXES}
            or pager.should_auto_pin(source)):
        return False
    # Infrastructure/private roots never gain admission through a snapshot.
    if path.parts[3] in {'local-llm', 'local-llm', 'agent-i-node', 'agent-i'}:
        return False
    # Only the existing public research output tree may enter from a phone role.
    # Chats, uploads, role configuration and all other role files remain excluded.
    public_research = '/home/user/agent_roles/agent-b/files/public_analysis/'
    if path.parts[3] == 'agent_roles' and not source.startswith(public_research):
        return False
    current = time.time() if now is None else now
    try:
        if heads is None:
            heads = json.loads(VERSION_HEADS.read_text())['heads']
        head = heads.get(asset_id) or {}
        if head.get('root') != source or not re.fullmatch(r'[a-f0-9]{64}', str(head.get('version_id', ''))):
            return False
        if page_rows is None:
            prefix = source.rstrip('/') + '/'
            with closing(sqlite3.connect('file:%s?mode=ro' % pager.STATE_DB, uri=True)) as conn:
                conn.row_factory = sqlite3.Row
                page_rows = [dict(row) for row in conn.execute(
                    "SELECT * FROM pages WHERE host='hostb' AND (path=? OR substr(path,1,?)=?)",
                    (source, len(prefix), prefix))]
        exact = [r for r in page_rows if r.get('path') == source and r.get('cloud_asset_id') == asset_id]
        if len(exact) != 1:
            return False
        row = exact[0]
        if (row.get('host') != 'hostb' or row.get('storage_pool') != 'MANAGED'
                or row.get('state') != 'WARM' or row.get('pinned')
                or float(row.get('lease_until') or 0) > current
                or not row.get('cloud_verified') or not row.get('snapshot_verified')
                or row.get('dirty') or row.get('annotation_status') != 'CURRENT'):
            return False
        for child in page_rows:
            if child.get('path') == source or not str(child.get('path', '')).startswith(source + '/'):
                continue
            if (child.get('storage_pool') != 'MANAGED' or child.get('pinned')
                    or child.get('state') in {'HOT', 'PINNED', 'ISOLATED'}
                    or float(child.get('lease_until') or 0) > current):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        return False


def source_is_allowed(source, asset_id=None, *, allow_unverified_migration=False):
    """Accept only a normalized child of an explicitly authorized hostb root."""
    if not isinstance(source, str) or not source.startswith("/"):
        return False
    path = PurePosixPath(source)
    if str(path) != source or ".." in path.parts:
        return False
    prefix_allowed = any(
        source.startswith(prefix) and source != prefix.rstrip("/")
        for prefix in ALLOWED_PREFIXES
    )
    exact = migration_entries(
        require_fingerprint=not allow_unverified_migration
    ).get(str(asset_id or ""))
    migration_allowed = bool(exact and exact.get("source") == source)
    return prefix_allowed or migration_allowed or registered_workspace_allowed(source, asset_id)


def run(args, *, capture=False, check=True):
    if len(args) > 4 and args[:3] == ['ssh', '-n', REMOTE]:
        args = args[:3] + [shlex.join(args[3:])]
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None,
                          stdin=subprocess.DEVNULL)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_empty_handle_probe(result):
    output = (result.stdout or "") + (getattr(result, "stderr", None) or "")
    if any(line.startswith(("p", "f", "n")) for line in output.splitlines()):
        raise SystemExit("REFUSE_SOURCE_HAS_OPEN_HANDLES")
    if result.returncode != 1 or output.strip():
        raise SystemExit("REFUSE_SOURCE_HANDLE_PROBE_FAILED rc=%s" % result.returncode)


def handle_probe_command(source):
    """lsof 句柄探测命令。``-e`` 只传运行时**真正已挂载**的豁免点。

    Incident note: 根因与修法 —— 这条探测此前**从未真正执行过一次**：

    lsof 的 ``-e`` 要求实参必须是一个*已挂载的文件系统*。``/tmp/fuse`` 在 hostb 上
    自 <time> 起只是一个普通空目录(EXISTS_NOT_MOUNT,属主 user),
    lsof 拿到它当场报 ``"-e /tmp/fuse" is not a mounted file system`` 并打印 usage
    后退出 —— 连一个文件都没探。返回码恰好是 1(与"无句柄"同码),但 stdout 非空,
    于是 ``require_empty_handle_probe`` 落到 ``REFUSE_SOURCE_HANDLE_PROBE_FAILED``。

    后果不是漏报而是**永久拉黑**:该拒绝被写进 pager 的 ``evict_blocked`` 台账,
    而那个台账(与 ``archive_blocked`` 不同)**没有任何过期或重试机制**。
    <date> 实查:747 个 blocked 页里 383 个是这一条,全部产生于压力触发后的
    2.4 天内,主盘因此卡在 free=6.2% 腾不动(目标 15%)。

    判别实验(同一页 /home/user/research-a/ANALYSIS、同一时刻):
        传入非挂载点   -> rc=1, 输出 677 字节(报错+usage)  -> 判 PROBE_FAILED
        只传已挂载的   -> rc=1, 输出 **0** 字节            -> 正确的"无句柄"

    安全边界一字未放宽:
      * 重叠检查(``REFUSE_HANDLE_PROBE_EXEMPTION_OVERLAP``)仍对**全部**豁免点执行,
        与挂载与否无关 —— 否则卸载一个 FUSE 点就能绕开目标路径校验。
      * ``-e`` 的唯一作用是阻止 lsof 去 stat 可能挂死的 FUSE 文件系统;一个**没有
        挂载**的路径本来就不存在这种挂死风险,跳过它不改变任何探测语义。
      * ``mountpoint`` 工具缺失时以 rc=3 **fail-closed** 退出,绝不降级成"不传豁免"
        去裸探 FUSE —— 那会把挂死风险换回来。rc=3 不等于 1,调用方照旧判 PROBE_FAILED。
    """
    target = PurePosixPath(source)
    exemptions = ("/run/user/1000/doc", "/run/user/1000/gvfs", "/tmp/fuse")
    if not target.is_absolute() or ".." in target.parts:
        raise SystemExit("REFUSE_HANDLE_PROBE_TARGET")
    for mount in exemptions:
        excluded = PurePosixPath(mount)
        if target == excluded or target in excluded.parents or excluded in target.parents:
            raise SystemExit("REFUSE_HANDLE_PROBE_EXEMPTION_OVERLAP")
    return (
        "command -v mountpoint >/dev/null 2>&1 || exit 3; "
        "set -- ; "
        'for m in %s; do mountpoint -q "$m" && set -- "$@" -e "$m"; done; '
        'exec sudo -n lsof "$@" -Fn +D %s'
    ) % (" ".join(shlex.quote(m) for m in exemptions), shlex.quote(source))


def process_probe_command(source):
    import base64
    encoded = base64.b64encode(os.fsencode(source)).decode('ascii')
    return shlex.join(['sudo', '-n', '/usr/bin/python3',
                      '/home/user/.coldstore/bin/workspace_archive_remote.py',
                      'process-refs', '--path-b64', encoded])


def require_empty_process_probe(result):
    try:
        if result.returncode != 0:
            raise ValueError('process probe exit')
        data = json.loads(result.stdout)
        if (data.get('schema') != 'workspace-process-refs/v1'
                or type(data.get('checked')) is not int or data['checked'] < 1
                or not isinstance(data.get('hits'), list)):
            raise ValueError('process probe schema')
    except (ValueError, TypeError, AttributeError):
        raise SystemExit('REFUSE_SOURCE_PROCESS_PROBE_FAILED')
    if data['hits']:
        raise SystemExit('REFUSE_SOURCE_RUNNING_PROCESS_REFERENCE')


def rows(path):
    with Path(path).open(encoding="utf-8") as f:
        return [r for r in csv.reader(f, delimiter="\t") if r and not r[0].startswith("#")]


def append_tsv(path, row):
    with Path(path).open("a", encoding="utf-8", newline="") as f:
        csv.writer(f, delimiter="\t", lineterminator="\n").writerow(row)
        f.flush()
        os.fsync(f.fileno())


def eviction_order(row):
    """Drain Function batches first so their verified deletion can unlock the next batch."""
    source = str(row.get("original_path", ""))
    function_batch = source.startswith((
        "/home/user/asset-pool-v3/",
        "/data/asset-pool-v3/",
    ))
    return (0 if function_batch else 1, int(row["size"]), row["asset_id"])


def choose_asset(requested=None, *, allow_unverified_migration=False):
    catalog = [json.loads(x) for x in (WS / "cloud_asset_catalog.jsonl").read_text().splitlines()]
    candidates = []
    for r in catalog:
        if requested and r["asset_id"] != requested:
            continue
        if (r.get("machine") == "hostb" and r.get("cloud_state") == "confirmed"
                and r.get("local_state") == "replicated"
                and not r["original_path"].startswith("manifest://")
                and source_is_allowed(
                    r["original_path"], r["asset_id"],
                    allow_unverified_migration=allow_unverified_migration)):
            candidates.append(r)
    if not candidates:
        raise SystemExit("NO_ELIGIBLE_CONFIRMED_hostb_ASSET")
    return min(candidates, key=eviction_order)


def build_manifest(asset, source, version=None):
    remote_out = f"/tmp/baidu-evict-manifest-{os.getpid()}"
    cmd = (
        f"rm -rf -- {shlex.quote(remote_out)} && mkdir -p {shlex.quote(remote_out)} && "
        f"python3 {shlex.quote(REMOTE_META + '/vault_v2_manifest.py')} build "
        f"--label {shlex.quote(asset)} --base {shlex.quote(source)} "
        f"--cutoff-epoch 4102444800 --output {shlex.quote(remote_out)}"
    )
    result = run(["ssh", "-n", REMOTE, cmd], capture=True)
    meta = json.loads(result.stdout.strip().splitlines()[-1])
    try:
        with tempfile.TemporaryDirectory(prefix="source-verify-manifest-") as temporary:
            for suffix, hash_key in (("files0.gz", "files0_sha256"), ("jsonl.gz", "search_sha256")):
                destination = Path(temporary) / f"{asset}.{suffix}"
                run(["scp", "-q", f"{REMOTE}:{remote_out}/{asset}.{suffix}", str(destination)])
                if sha(destination) != meta[hash_key]:
                    raise SystemExit("REFUSE_SOURCE_VERIFY_MANIFEST_HASH_MISMATCH")
                if version:
                    target = manifest_proof_path(asset, version, suffix, meta[hash_key])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() and sha(target) != meta[hash_key]:
                        raise SystemExit("REFUSE_VERSION_MANIFEST_CONTENT_COLLISION")
                    if not target.exists():
                        staging = target.with_suffix(target.suffix + '.tmp.%s' % os.getpid())
                        shutil.copy2(destination, staging)
                        os.replace(staging, target)
    finally:
        run(["ssh", "-n", REMOTE, "rm", "-rf", "--", remote_out])
    return meta


def current_archive_version(asset):
    try:
        head = json.loads((WS / "vault_v2_heads.json").read_text())["heads"][asset]
        version = head["version_id"]
        if not re.fullmatch(r"[0-9a-f]{64}", str(version)):
            raise ValueError("invalid version")
        return version
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit("REFUSE_CURRENT_ARCHIVE_VERSION_UNAVAILABLE") from error


def manifest_proof_path(asset, version, suffix, digest):
    identity = hashlib.sha256((asset + '|' + version + '|' + suffix + '|' + digest).encode()).hexdigest()
    return WS / 'manifests' / ('verified-' + identity + '.' + suffix)


def legacy_manifest_evidence(asset, version):
    """Manifest digests recorded by the retired restore-verification flow.

    Kept read-only so the ~2000 per-version manifests it already produced stay
    valid; nothing writes this table any more."""
    path = WS / "cloud_asset_restore_tests.tsv"
    if not path.exists():
        return None
    for row in reversed(rows(path)):
        if len(row) >= 5 and row[0] == asset and row[2] == ARCHIVE_PROOF_CONTENT and row[3] == "PASS":
            values = {}
            for item in row[4].split(";"):
                key, sep, value = item.partition("=")
                if sep:
                    values[key] = value
            if values.get("archive_version") == version:
                return values
    return None


def version_manifest_digests(asset, version):
    """(files0_sha256, search_sha256) recorded for this asset version, or None."""
    ledger = WS / VERSION_MANIFESTS
    if ledger.exists():
        for row in reversed(rows(ledger)):
            if (len(row) >= 5 and row[0] == asset and row[2] == version
                    and SHA256_RE.fullmatch(row[3] or "") and SHA256_RE.fullmatch(row[4] or "")):
                return row[3], row[4]
    legacy = legacy_manifest_evidence(asset, version)
    if legacy:
        files0 = legacy.get("file_manifest_files0_sha256") or ""
        search = legacy.get("file_manifest_search_sha256") or ""
        if SHA256_RE.fullmatch(files0) and SHA256_RE.fullmatch(search):
            return files0, search
    return None


def version_manifest_files(asset, version=None):
    version = current_archive_version(asset) if version is None else version
    digests = version_manifest_digests(asset, version)
    if not digests:
        return []
    result = []
    for suffix, digest in (("files0.gz", digests[0]), ("jsonl.gz", digests[1])):
        path = manifest_proof_path(asset, version, suffix, digest)
        if not path.is_file() or path.is_symlink() or sha(path) != digest:
            return []
        result.append((path, digest))
    return result


def file_manifest_identity(asset, version=None):
    files = version_manifest_files(asset, version)
    return hashlib.sha256(json.dumps([(path.name, digest) for path, digest in files]).encode()).hexdigest() if files else None


def ensure_version_manifest(asset, source, version):
    """Per-version file manifest (paths/sizes/mtimes, no hashing, no download).

    This is the "what exactly was deleted" description the user required for
    every cloud-only asset.  Built locally on hostb from the live tree, so it is
    only meaningful when the tree still equals the archived snapshot -- the
    caller proves that before and after."""
    if version_manifest_files(asset, version):
        return version_manifest_digests(asset, version)
    manifest = build_manifest(asset, source, version=version)
    if current_archive_version(asset) != version:
        raise SystemExit("REFUSE_ARCHIVE_VERSION_CHANGED_DURING_MANIFEST")
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    append_tsv(WS / VERSION_MANIFESTS, [asset, now, version, manifest["files0_sha256"],
                                        manifest["search_sha256"], str(manifest.get("files", "")),
                                        str(manifest.get("bytes", ""))])
    if not version_manifest_files(asset, version):
        raise SystemExit("REFUSE_VERSION_MANIFEST_NOT_MATERIALIZED")
    return manifest["files0_sha256"], manifest["search_sha256"]


def three_copy_evidence(asset):
    version = current_archive_version(asset)
    identity = file_manifest_identity(asset, version)
    path = WS / "cloud_asset_three_copy.tsv"
    return any(identity and len(row) >= 7 and row[0] == asset and row[5] == version and row[6] == identity
               for row in rows(path)) if path.is_file() else False


def snapshot_proof_content(asset, source, fingerprint):
    path = WS / "workspace_snapshot_proofs.tsv"
    if not path.exists():
        return None
    for row in reversed(rows(path)):
        if (len(row) >= 11 and row[0] == asset and row[3] == source
                and row[7] == "PASS" and row[9] == fingerprint):
            try:
                content = json.loads(row[10])
            except json.JSONDecodeError:
                return None
            if (content.get("sha256") == fingerprint
                    and int(content.get("bytes") or -1) >= 0):
                return content
    return None


def archive_snapshot_proof(asset, source):
    """Latest PASS proof of what ``source`` looked like when its cloud copy was made.

    Returns ``{"kind": "metadata"|"content", "sha256", "entries", "bytes",
    "consistency_fingerprint", "at", "version_id"}`` or None.  ``version_id``
    is only present on rows written after <date> (workspace_archive.py
    appends the committed head); older rows are accepted as long as they are the
    newest PASS row for the pair, which is what the archiver produced last.
    """
    path = WS / "workspace_snapshot_proofs.tsv"
    if not path.exists():
        return None
    for row in reversed(rows(path)):
        if len(row) < 10 or row[0] != asset or row[3] != source or row[7] != "PASS":
            continue
        reason = row[8]
        if ARCHIVE_PROOF_METADATA in reason:
            kind = "metadata"
        elif ARCHIVE_PROOF_CONTENT in reason:
            kind = "content"
        else:
            continue
        if not SHA256_RE.fullmatch(row[4] or ""):
            continue
        version_id = row[11] if len(row) >= 12 and SHA256_RE.fullmatch(row[11] or "") else None
        try:
            entries, size = int(row[5] or 0), int(row[6] or 0)
        except ValueError:
            continue
        return {"kind": kind, "sha256": row[4], "entries": entries, "bytes": size,
                "consistency_fingerprint": row[9], "at": row[1], "version_id": version_id}
    return None


def remote_snapshot(source):
    """Metadata snapshot (path/kind/mode/size/mtime_ns of every entry) of a hostb tree.

    Same helper and same hash the archiver uses, so equality with the archive
    proof means "unchanged since upload" without reading file contents."""
    encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
    result = run(["ssh", "-n", REMOTE, "sudo", "-n", REMOTE_HELPER,
                  "snapshot", "--path-b64", encoded], capture=True)
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise SystemExit("REFUSE_SNAPSHOT_PARSE") from exc
    if not SHA256_RE.fullmatch(str(value.get("sha256") or "")):
        raise SystemExit("REFUSE_SNAPSHOT_INVALID")
    return value


def current_local_digest(source, proof):
    """Digest of the live tree in the comparator the proof was recorded with."""
    if proof["kind"] == "metadata":
        return remote_snapshot(source)["sha256"]
    return remote_content_fingerprint(source)["sha256"]


def assert_local_matches_archive(asset, source, proof, *, pg=None, stage="before_delete"):
    """Refuse (and mark the page dirty) unless the live tree equals the archived one."""
    got = current_local_digest(source, proof)
    if got != proof["sha256"]:
        (pg or pager.WorkspacePager()).mark_dirty(
            "hostb", source,
            f"eviction refused ({stage}): local tree differs from archived snapshot; re-archive required")
        raise SystemExit(
            "REFUSE_LOCAL_CHANGED_REARCHIVE_REQUIRED asset=%s comparator=%s expected=%s got=%s stage=%s" %
            (asset, proof["kind"], proof["sha256"], got, stage))
    return got


def require_whole_root_head(asset, source):
    """A frozen-subset (manifest://) head never authorises deleting the whole root."""
    try:
        head = json.loads((WS / "vault_v2_heads.json").read_text(encoding="utf-8"))["heads"][asset]
        root = str(head["root"])
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit("REFUSE_CURRENT_VERSION_HEAD_UNREADABLE") from exc
    if root != source:
        raise SystemExit(f"REFUSE_PARTIAL_ARCHIVE_HEAD asset={asset} head_root={root} source={source}")
    return root


def remote_content_fingerprint(source):
    encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
    result = run([
        "ssh", "-n", REMOTE, "sudo", "-n",
        "/home/user/.coldstore/bin/workspace_archive_remote.py",
        "content-fingerprint", "--path-b64", encoded,
    ], capture=True)
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise SystemExit("REFUSE_CONTENT_FINGERPRINT_PARSE") from exc
    if len(str(value.get("sha256") or "")) != 64:
        raise SystemExit("REFUSE_CONTENT_FINGERPRINT_INVALID")
    return value


def append_snapshot_proof(asset, source, manifest, content, *,
                          proof_reason="baidu_native_download_decrypt_tar_source_match;content_fingerprint_v2"):
    proofs = WS / "workspace_snapshot_proofs.tsv"
    existing = [row for row in rows(proofs) if len(row) >= 8 and row[0] == asset
                and row[3] == source and row[7] == "PASS"] if proofs.exists() else []
    if existing and any(len(row) >= 10 and row[9] == content["sha256"] for row in existing):
        return
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    append_tsv(proofs, [
        asset, now, "hostb", source, content["sha256"],
        str(content.get("entries") or manifest.get("files") or 0),
        str(content.get("bytes") or manifest.get("bytes") or 0), "PASS",
        proof_reason,
        content["sha256"], json.dumps(content, ensure_ascii=False, sort_keys=True),
    ])


def three_copy_register(asset):
    with (WS / ".metadata_sync.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _three_copy_register_locked(asset)


def _three_copy_register_locked(asset):
    version = current_archive_version(asset)
    manifest_identity = file_manifest_identity(asset, version)
    if not manifest_identity:
        raise SystemExit('REFUSE_VERSION_FILE_MANIFEST_MISSING')
    local = WS / ".last_synced_catalog.jsonl"
    receipt_path = WS / ".metadata_sync_receipt.json"
    if not local.is_file() or not receipt_path.is_file():
        raise SystemExit("REFUSE_FROZEN_METADATA_SYNC_RECEIPT_MISSING")
    receipt = json.loads(receipt_path.read_text())
    catalog_rows = [json.loads(line) for line in local.read_text().splitlines() if line.strip()]
    if not any(row.get("asset_id") == asset and row.get("cloud_state") == "confirmed"
               and row.get("current_version_id") == version
               for row in catalog_rows):
        raise SystemExit("REFUSE_ASSET_ABSENT_FROM_SYNC_SNAPSHOT")
    remote = f"{REMOTE_META}/cloud_asset_catalog.jsonl"
    remote_hash = run(["ssh", "-n", REMOTE, "sha256sum", remote], capture=True).stdout.split()[0]
    local_hash = sha(local)
    if remote_hash != local_hash or local_hash != receipt.get("catalog_sha256"):
        raise SystemExit("REFUSE_REMOTE_METADATA_HASH_MISMATCH")
    cipher = ICLOUD / "cloud_asset_catalog.jsonl.gpg"
    if not cipher.is_file():
        raise SystemExit("REFUSE_ICLOUD_METADATA_MISSING")
    if sha(cipher) != receipt.get("catalog_cipher_sha256"):
        raise SystemExit("REFUSE_ICLOUD_METADATA_SNAPSHOT_MISMATCH")
    for path, expected in version_manifest_files(asset, version):
        frozen = (receipt.get('verified_manifests') or {}).get(path.name) or {}
        remote_digest = run(['ssh', '-n', REMOTE, 'sha256sum', REMOTE_META + '/manifests/' + path.name], capture=True).stdout.split()[0]
        encrypted = ICLOUD / (path.name + '.gpg')
        if (frozen.get('sha256') != expected or remote_digest != expected or not encrypted.is_file()
                or sha(encrypted) != frozen.get('cipher_sha256')):
            raise SystemExit('REFUSE_VERSION_MANIFEST_THREE_COPY_MISMATCH')
    if current_archive_version(asset) != version:
        raise SystemExit("REFUSE_ARCHIVE_VERSION_CHANGED_DURING_METADATA_SYNC")
    if not three_copy_evidence(asset):
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        append_tsv(WS / "cloud_asset_three_copy.tsv", [asset, now, local_hash, remote_hash, sha(cipher), version, manifest_identity])


def assert_migration_postconditions(asset, expected_path):
    catalog_rows = [
        json.loads(line) for line in (WS / "cloud_asset_catalog.jsonl").read_text().splitlines()
        if line.strip()
    ]
    catalog_asset = [row for row in catalog_rows if row.get("asset_id") == asset]
    page_rows = pager.WorkspacePager().status(asset)["rows"]
    if (len(catalog_asset) != 1 or catalog_asset[0].get("original_path") != expected_path
            or catalog_asset[0].get("local_state") != "cloud_only"):
        raise SystemExit("REFUSE_POST_DELETE_CATALOG_NOT_CLOUD_ONLY_AT_EXPECTED_PATH")
    if (len(page_rows) != 1 or page_rows[0].get("path") != expected_path
            or int(page_rows[0].get("local_present") or 0) != 0):
        raise SystemExit("REFUSE_POST_DELETE_PAGER_NOT_SINGLE_COLD_PAGE")


def repair_completed_migration(asset):
    exact = migration_entries().get(asset)
    if not exact or not migration_target_allowed(exact.get("target_path")):
        raise SystemExit("REFUSE_REPAIR_MIGRATION_NOT_EXACTLY_APPROVED")
    source, target = exact["source"], exact["target_path"]
    source_exists = run(["ssh", "-n", REMOTE, "test", "-e", source], check=False)
    target_exists = run(["ssh", "-n", REMOTE, "test", "-e", target], check=False)
    if source_exists.returncode == 0 or target_exists.returncode == 0:
        raise SystemExit("REFUSE_REPAIR_REQUIRES_SOURCE_AND_COLD_TARGET_ABSENT")
    latest_sources = {
        row[3]: row for row in rows(WS / "vault_v2_sources.tsv") if len(row) >= 6
    }
    if asset not in latest_sources or latest_sources[asset][2] != target:
        raise SystemExit("REFUSE_REPAIR_LOGICAL_SOURCE_NOT_MIGRATED")
    fingerprint = str(exact.get("expected_content_fingerprint") or "")
    if not SHA256_RE.fullmatch(fingerprint):
        raise SystemExit("REFUSE_REPAIR_MIGRATION_FINGERPRINT_MISSING")
    head = json.loads((WS / "vault_v2_heads.json").read_text(encoding="utf-8")).get(
        "heads", {}
    ).get(asset)
    if not head or not head.get("version_id"):
        raise SystemExit("REFUSE_REPAIR_CURRENT_VERSION_HEAD_MISSING")
    content = snapshot_proof_content(asset, source, fingerprint)
    if content is None:
        raise SystemExit("REFUSE_REPAIR_SOURCE_SNAPSHOT_PROOF_MISSING")
    append_snapshot_proof(
        asset, target, content, content,
        proof_reason=("physical_pool_migration;cloud_current_head_retained;"
                      "content_fingerprint_v2"),
    )
    run([str(WS / "cloud_asset_catalog.py")])
    pager.WorkspacePager().relocate_asset(
        asset, "hostb", target,
        "resume physical pool migration after verified source deletion",
        local_present=0, verified_absent_paths=[source], verified_snapshot=True,
    )
    run([str(COLDSTORE_BIN / "ws"), "index", "--rebuild"])
    run([str(COLDSTORE_BIN / "ws"), "page", "sync", "--json"])
    run([str(WS / "vault_v2_sync.py")])
    assert_migration_postconditions(asset, target)
    print(f"MIGRATION_REPAIR_PASS asset={asset} target={target}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asset")
    ap.add_argument("--execute-delete", action="store_true")
    ap.add_argument("--repair-migration", action="store_true")
    ap.add_argument("--migration", action="store_true",
                    help="allow only an exact approved migration-manifest entry")
    args = ap.parse_args()
    if not args.asset:
        raise SystemExit("REFUSE_EXPLICIT_ASSET_REQUIRED")
    lock_name = hashlib.sha256(args.asset.encode()).hexdigest()
    with (WS / (".asset-operation-" + lock_name + ".lock")).open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("WAIT_ASSET_OPERATION_LOCK")
            return 3
        return execute(args)


def execute(args):
    if sum(map(int, (args.execute_delete, args.repair_migration))) != 1:
        raise SystemExit("REFUSE_EXACTLY_ONE_ACTION_REQUIRED")
    if args.migration and (not args.execute_delete or not args.asset):
        raise SystemExit("REFUSE_MIGRATION_REQUIRES_EXPLICIT_DELETE_ASSET")
    if args.repair_migration:
        if not args.asset:
            raise SystemExit("REFUSE_REPAIR_MIGRATION_ASSET_REQUIRED")
        repair_completed_migration(args.asset)
        return 0

    run([str(WS / "cloud_asset_catalog.py")])
    pg = None
    if args.migration:
        meta = choose_asset(args.asset)
    else:
        pg = pager.WorkspacePager()
        pools = pg.pool_status()
        migration_state = str(pg.policy.get("pool_migration_state") or "UNKNOWN")
        if migration_state != "COMPLETE":
            if pg.policy.get("evict_enabled"):
                raise SystemExit("REFUSE_EVICTION_BEFORE_POOL_MIGRATION_COMPLETE")
            print(f"NO_PRESSURE_EVICTION pool_migration_state={migration_state}")
            return 0
        if not pg.policy.get("evict_enabled"):
            print("NO_PRESSURE_EVICTION evict_enabled=false")
            return 0
        if not pools["managed"]["eviction_active"]:
            print("NO_PRESSURE_EVICTION managed_free_ratio=%.6f" %
                  pools["managed"]["free_ratio"])
            return 0
        candidates = pg.eviction_candidates()
        if not candidates:
            raise SystemExit("REFUSE_PRESSURE_WITHOUT_ELIGIBLE_WARM_PAGE")
        eligible_ids = [row["asset_id"] for row in candidates]
        if args.asset and args.asset not in eligible_ids:
            raise SystemExit("REFUSE_ASSET_NOT_CURRENT_EVICTION_CANDIDATE")
        meta = choose_asset(args.asset or eligible_ids[0])
    asset, source = meta["asset_id"], meta["original_path"]
    if not source_is_allowed(source, asset):
        raise SystemExit("REFUSE_SOURCE_PATH_TOO_BROAD")
    exact = migration_entries().get(asset)
    if args.migration and not (exact and exact.get("source") == source):
        raise SystemExit("REFUSE_MIGRATION_ASSET_NOT_EXACTLY_APPROVED")
    if args.migration and not migration_target_allowed(exact.get("target_path")):
        raise SystemExit("REFUSE_MIGRATION_TARGET_NOT_MANAGED")

    # ---- trust-the-cloud proof chain (no download) ----------------------------
    version = current_archive_version(asset)
    require_whole_root_head(asset, source)
    proof = archive_snapshot_proof(asset, source)
    if proof is None:
        raise SystemExit(f"REFUSE_ARCHIVE_SNAPSHOT_PROOF_MISSING asset={asset}")
    if proof.get("version_id") and proof["version_id"] != version:
        raise SystemExit("REFUSE_ARCHIVE_SNAPSHOT_PROOF_STALE_VERSION asset=%s proof=%s head=%s" %
                         (asset, proof["version_id"], version))
    assert_local_matches_archive(asset, source, proof, pg=pg, stage="proof")
    print(f"ARCHIVE_SNAPSHOT_MATCH asset={asset} comparator={proof['kind']} "
          f"sha256={proof['sha256']} entries={proof['entries']} bytes={proof['bytes']} "
          f"version={version} repeat_download=false")
    current = None
    if args.migration:
        current = remote_content_fingerprint(source)
        if exact["expected_content_fingerprint"] != current["sha256"]:
            raise SystemExit("REFUSE_MIGRATION_MANIFEST_FINGERPRINT_MISMATCH")
        target = exact["target_path"]
        link = run(["ssh", "-n", REMOTE, "readlink", target], capture=True, check=False)
        if link.returncode == 0 and link.stdout.strip() != source:
            raise SystemExit("REFUSE_MIGRATION_TARGET_SYMLINK_MISMATCH")
        if link.returncode != 0:
            occupied = run(["ssh", "-n", REMOTE, "test", "-e", target], check=False)
            if occupied.returncode == 0:
                raise SystemExit("REFUSE_MIGRATION_TARGET_OCCUPIED")
        page_rows = [
            row for row in pager.WorkspacePager().status(asset)["rows"]
            if row.get("cloud_asset_id") == asset
        ]
        if len(page_rows) != 1:
            raise SystemExit(
                f"REFUSE_MIGRATION_PAGE_ROW_COUNT asset={asset} count={len(page_rows)}"
            )

    # Description of what is about to disappear locally, replicated three ways.
    ensure_version_manifest(asset, source, version)
    run([str(WS / "vault_v2_sync.py")])
    three_copy_register(asset)
    if not three_copy_evidence(asset):
        raise SystemExit("REFUSE_CURRENT_VERSION_METADATA_PROOF_MISSING")

    gate = run([str(WS / "cloud_asset_delete_gate.py"), asset], capture=True, check=False)
    print(gate.stdout, end="")
    if gate.returncode or "DELETE_PREFLIGHT_PASS" not in gate.stdout:
        failed = [line.split('=', 1)[0] for line in gate.stdout.splitlines() if line.endswith('=FAIL')]
        raise SystemExit("REFUSE_DELETE_GATE_NOT_PASS checks=" + ','.join(failed))
    lsof_cmd = handle_probe_command(source)
    handles = run(["ssh", "-n", REMOTE, lsof_cmd], capture=True, check=False)
    require_empty_handle_probe(handles)
    process_probe = run(["ssh", "-n", REMOTE, process_probe_command(source)],
                        capture=True, check=False)
    require_empty_process_probe(process_probe)
    resolved = run(["ssh", "-n", REMOTE, "readlink", "-f", source], capture=True).stdout.strip()
    if resolved != source or not source_is_allowed(source, asset):
        raise SystemExit(f"REFUSE_SOURCE_PATH_RESOLUTION source={source} resolved={resolved}")
    if current_archive_version(asset) != version:
        raise SystemExit("REFUSE_ARCHIVE_VERSION_CHANGED_BEFORE_DELETE")
    assert_local_matches_archive(asset, source, proof, pg=pg, stage="before_delete")
    run(["ssh", "-n", REMOTE, "sudo", "-n", "rm", "-rf", "--", source])
    absent = run(["ssh", "-n", REMOTE,
                  "sudo -n test ! -e %s && sudo -n test ! -L %s" %
                  (shlex.quote(source), shlex.quote(source))], check=False)
    if absent.returncode != 0:
        raise SystemExit("REFUSE_SOURCE_ABSENCE_NOT_PROVEN_AFTER_DELETE")
    if args.migration:
        target = exact["target_path"]
        link = run(["ssh", "-n", REMOTE, "readlink", target], capture=True, check=False)
        if link.returncode == 0:
            if link.stdout.strip() != source:
                raise SystemExit("REFUSE_MIGRATION_TARGET_SYMLINK_MISMATCH")
            run(["ssh", "-n", REMOTE, "unlink", "--", target])
        occupied = run(["ssh", "-n", REMOTE, "test", "-e", target], check=False)
        if occupied.returncode == 0:
            raise SystemExit("REFUSE_MIGRATION_TARGET_OCCUPIED")
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        append_tsv(WS / "vault_v2_sources.tsv", [
            now, "hostb", target, asset, str(meta["size"]),
            str(meta.get("description") or "") + "; physical pool migration",
        ])
    pg = pager.WorkspacePager()
    if args.migration:
        pg.relocate_asset(
            asset, "hostb", exact["target_path"],
            "physical pool migration; cloud current head retained; no repeat download",
            local_present=0,
            verified_absent_paths=[source],
            verified_snapshot=True,
        )
        append_snapshot_proof(
            asset, exact["target_path"], current, current,
            proof_reason=("physical_pool_migration;cloud_current_head_retained;"
                          "content_fingerprint_v2"),
        )
    else:
        pg.mark_evicted(asset, "watermark eviction; trust-the-cloud contract; no repeat download")
    run([str(WS / "cloud_asset_catalog.py")])
    run([str(COLDSTORE_BIN / "ws"), "index", "--rebuild"])
    run([str(COLDSTORE_BIN / "ws"), "page", "sync", "--json"])
    run([str(WS / "vault_v2_sync.py")])
    expected_path = exact["target_path"] if args.migration else source
    assert_migration_postconditions(asset, expected_path)
    print(f"EVICT_PASS asset={asset} bytes={meta['size']} source_deleted=true "
          f"repeat_download=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
