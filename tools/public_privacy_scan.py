#!/usr/bin/env python3
"""Fail-closed privacy / instance-metadata scanner for the public tree.

Secret scanners catch credentials.  They do not catch the things that leaked in practice:
absolute home paths, LAN/VPN addresses, ssh targets, account-local directory hashes,
operator order quotes, dated incident narratives, internal project/engine names.

Two layers:
  * generic rules (below): anything that is by construction deployment-specific.
  * an optional deny wordlist (COLDSTORE_PRIVACY_DENYLIST, one regex per line) kept OUTSIDE
    the repository — the real names never enter the tree, not even as a pattern.
    If the variable is set but the file is unreadable the scan exits 2 (never silently
    runs with fewer rules).

Allowlist (RFC 5737 doc addresses, example users) is explicit; everything else that looks
like a real path/host/date fails.  Exit 0 = clean, 1 = findings, 2 = misconfiguration.
"""
import os, re, sys
_POS = [a for a in sys.argv[1:] if not a.startswith("--")]
ROOT = os.path.abspath(_POS[0] if _POS else os.path.join(os.path.dirname(__file__), ".."))
ALLOW_USERS = {"user", "alice", "example", "USER", "runner", "root", "test", "xxx"}
ALLOW_HOSTS = {"host-a", "host-b", "hostb", "localhost", "example.com", "host"}
GENERIC = [
    ("HOME_PATH",   re.compile(r"/(?:Users|home)/([A-Za-z0-9_.-]+)")),
    ("SSH_TARGET",  re.compile(r"\b([a-z][a-z0-9_.-]{1,30})@([a-z0-9][a-z0-9.-]{1,60})\b")),
    ("PRIVATE_IP",  re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b")),
    ("PUBLIC_IP",   re.compile(r"\b(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.|0\.0\.0\.0)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("DATE",        re.compile(r"\b20[12]\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b")),
    ("HEX32",       re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{32}(?![0-9a-fA-F])")),
    ("EMAIL",       re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("CN_MOBILE",   re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("TASK_ID",     re.compile(r"\bhd-\d{8}-\d{6}-[a-z0-9]{4}\b")),
    ("OPERATOR_QUOTE", re.compile(r"(?:user order|用户令|用户原话)\s*[\"「]")),
    ("VENDOR_ROOT", re.compile(r"来自：本地电脑")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("TOKEN",       re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})")),
]
SKIP_DIRS = {".git", "__pycache__"}
SKIP_FILES = {"public_privacy_scan.py"}  # self: patterns would self-match

def release_mode():
    """Release gate: denylist is mandatory. Enabled by --require-denylist or COLDSTORE_RELEASE_SCAN=1.
    Missing/unreadable denylist -> exit 2 (never a PASS)."""
    return "--require-denylist" in sys.argv or os.environ.get("COLDSTORE_RELEASE_SCAN") == "1"

def load_denylist():
    p = os.environ.get("COLDSTORE_PRIVACY_DENYLIST")
    if not p:
        if release_mode():
            print("DENYLIST_REQUIRED release scan refuses to run without COLDSTORE_PRIVACY_DENYLIST", file=sys.stderr); sys.exit(2)
        return []
    try:
        lines = [l.strip() for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#")]
    except OSError as e:
        print(f"DENYLIST_UNREADABLE {p}: {e}", file=sys.stderr); sys.exit(2)
    return [("DENY", re.compile(l)) for l in lines]

def allowed(kind, m):
    if kind == "HOME_PATH": return m.group(1) in ALLOW_USERS
    if kind == "SSH_TARGET": return m.group(2).startswith("example.") or (m.group(1) in ALLOW_USERS and m.group(2) in ALLOW_HOSTS)
    if kind == "EMAIL": return m.group(0).endswith(("example.com", "example.invalid"))
    if kind == "HEX32":  # sha256 halves / published wheel digests are 64; 32 alone is suspicious
        return False
    return False

def main():
    rules = GENERIC + load_denylist(); findings = 0
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f in SKIP_FILES: continue
            p = os.path.join(d, f)
            try: text = open(p, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                print(f"BINARY_OR_UNREADABLE {os.path.relpath(p, ROOT)}"); findings += 1; continue
            for i, line in enumerate(text.splitlines(), 1):
                for kind, rx in rules:
                    for m in rx.finditer(line):
                        if allowed(kind, m): continue
                        findings += 1
                        print(f"{kind}\t{os.path.relpath(p, ROOT)}:{i}\t{line.strip()[:120]}")
    deny_on = bool(os.environ.get('COLDSTORE_PRIVACY_DENYLIST'))
    if release_mode() and not deny_on:
        print("DENYLIST_REQUIRED", file=sys.stderr); sys.exit(2)
    print(f"PRIVACY_SCAN {'FAIL' if findings else 'PASS'} findings={findings} denylist={'on' if deny_on else 'off'} mode={'release' if release_mode() else 'dev'}")
    sys.exit(1 if findings else 0)
if __name__ == "__main__": main()
