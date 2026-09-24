#!/usr/bin/env python3
"""Move one exact unreferenced vault blob to Baidu recycle bin via its client.

This uses the logged-in desktop client's own Vue deletion path.  It accepts
only opaque v2 blob names and independently resolves the exact cached cloud
metadata before and after submission.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
from pathlib import PurePosixPath

import websocket

from baidu_client_download import APP_SUPPORT, DEVTOOLS_JSON, DownloadRefused, _devtools_page

CLOUD_BASE = os.environ.get("COLDSTORE_CLOUD_BASE", "/ColdArchive")
BLOB_RE = re.compile(r"^[0-9a-f]{64}\.blob$")


def filecache_db():
    matches = sorted(APP_SUPPORT.glob("*/filecache.db"))
    if len(matches) != 1:
        raise DownloadRefused(f"REFUSE_FILECACHE_DB_COUNT count={len(matches)}")
    return matches[0]


def exact_metadata(cloud_path):
    path = PurePosixPath(cloud_path)
    if (not path.is_absolute() or not str(path).startswith(CLOUD_BASE + "/v2/")
            or not BLOB_RE.fullmatch(path.name)):
        raise DownloadRefused(f"REFUSE_DELETE_PATH {cloud_path}")
    parent = str(path.parent).rstrip("/") + "/"
    with sqlite3.connect(f"file:{filecache_db()}?mode=ro", uri=True) as conn:
        rows = conn.execute(
            "SELECT fid,parent_path,server_filename,file_size FROM file_meta "
            "WHERE parent_path=? AND server_filename=? AND isdir=0",
            (parent, path.name),
        ).fetchall()
    if len(rows) != 1:
        raise DownloadRefused(
            f"REFUSE_DELETE_METADATA_COUNT count={len(rows)} path={cloud_path}"
        )
    return {"fid": int(rows[0][0]), "parent_path": rows[0][1],
            "filename": rows[0][2], "size": int(rows[0][3])}


def submit_recycle(cloud_path, endpoint=DEVTOOLS_JSON):
    page = _devtools_page(endpoint)
    encoded_path = urllib.parse.quote(cloud_path, safe="")
    expression = """
(()=>{
  let q=[document.querySelector('#app')&&document.querySelector('#app').__vue__], v=null;
  while(q.length){let x=q.shift(); if(!x)continue;
    if(x.$options&&x.$options.name==='mainPage'){v=x;break}
    q.push(...(x.$children||[]));
  }
  if(!v||typeof v.handleDelConfirm!=='function')return {error:'mainPage delete unavailable'};
  v.deletion.scheduledFiles=[%s];
  v.deletion.skipFiles=[];
  v.deletion.delSharedFiles=false;
  v.deletion.callback=function(){};
  v.handleDelConfirm();
  return {submitted:true,path:%s};
})()
""" % (json.dumps(encoded_path), json.dumps(cloud_path, ensure_ascii=False))
    ws = websocket.create_connection(
        page["webSocketDebuggerUrl"], timeout=10, suppress_origin=True
    )
    try:
        ws.send(json.dumps({
            "id": 1, "method": "Runtime.evaluate",
            "params": {"expression": expression, "returnByValue": True},
        }))
        while True:
            response = json.loads(ws.recv())
            if response.get("id") == 1:
                break
    finally:
        ws.close()
    value = response.get("result", {}).get("result", {}).get("value", {})
    if not value.get("submitted"):
        raise DownloadRefused(
            "REFUSE_DELETE_SUBMIT " + json.dumps(response, ensure_ascii=False)[:2000]
        )
    return value


def wait_removed(cloud_path, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            exact_metadata(cloud_path)
        except DownloadRefused as exc:
            if "METADATA_COUNT count=0" in str(exc):
                return
            raise
        time.sleep(2)
    raise DownloadRefused(f"REFUSE_DELETE_CONFIRM_TIMEOUT path={cloud_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cloud_path")
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    before = exact_metadata(args.cloud_path)
    if before["size"] != args.expected_size:
        raise DownloadRefused(
            f"REFUSE_DELETE_SIZE expected={args.expected_size} actual={before['size']}"
        )
    if not args.execute:
        print(json.dumps({"verdict": "DELETE_PLAN_PASS", "cloud": before},
                         ensure_ascii=False, sort_keys=True))
        return
    submit_recycle(args.cloud_path)
    wait_removed(args.cloud_path, args.timeout)
    print(json.dumps({"verdict": "RECYCLE_PASS", "cloud": before},
                     ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except DownloadRefused as exc:
        print(str(exc))
        raise SystemExit(2)
