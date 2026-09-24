#!/usr/bin/env python3
"""Let existing cron ticks supervise one finite native Pager pass per mode.

The inherited flock, rather than a PID guess, prevents duplicate passes across
cron timeouts/restarts. No daemon, LLM, extra timer or deletion policy lives here.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path.home() / '.coldstore/state/pager_cycles'
MAINTENANCE = Path(__file__).resolve().with_name('workspace_pager_maintenance.py')


def atomic_json(path, data):
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(data, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_state(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def supervise(mode, root=ROOT, popen=subprocess.Popen):
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / (mode + '.json')
    lock = (root / (mode + '.lock')).open('a+')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            prior = read_state(state_path)
            return {'status': 'RUNNING', 'mode': mode,
                    'pid': prior.get('pid'), 'started_at': prior.get('started_at'),
                    'lock_held': True, 'completed': False}
        prior = read_state(state_path)
        if prior.get('status') == 'RUNNING':
            # The OS released the lock: that run is no longer alive. Record the
            # interruption before resuming from the Pager's persisted proofs.
            prior.update(status='INTERRUPTED', detected_at=time.time())
            atomic_json(root / (mode + '.previous.json'), prior)
        elif prior:
            atomic_json(root / (mode + '.previous.json'), prior)
        command = [sys.executable, str(Path(__file__).resolve()), mode,
                   '--worker-fd', str(lock.fileno()), '--state-root', str(root)]
        with (root / (mode + '.log')).open('w') as log:
            proc = popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                         start_new_session=True, pass_fds=(lock.fileno(),))
        # Do NOT LOCK_UN here: parent/child share the same open file description.
        # Closing only the parent's descriptor leaves the worker's lock intact.
        return {'status': 'STARTED', 'mode': mode, 'pid': proc.pid,
                'completed': False, 'previous_status': prior.get('status'),
                'previous_rc': prior.get('rc')}
    finally:
        lock.close()


def worker(mode, fd, root=ROOT, runner=subprocess.run):
    os.fstat(fd)  # inherited descriptor must actually exist
    state_path = root / (mode + '.json')
    state = {'status': 'RUNNING', 'mode': mode, 'pid': os.getpid(),
             'started_at': time.time(), 'completed': False}
    atomic_json(state_path, state)
    try:
        result = runner([sys.executable, '-u', str(MAINTENANCE), '--' + mode + '-only'],
                        stdin=subprocess.DEVNULL, pass_fds=(fd,))
        state.update(status='DONE' if result.returncode == 0 else 'FAILED',
                     rc=result.returncode, completed=True)
    except BaseException as exc:
        state.update(status='FAILED', rc=2, completed=True, error=type(exc).__name__)
        raise
    finally:
        state['finished_at'] = time.time()
        atomic_json(state_path, state)
    return state['rc']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('archive', 'pressure'))
    ap.add_argument('--worker-fd', type=int)
    ap.add_argument('--state-root', type=Path, default=ROOT)
    args = ap.parse_args()
    if args.worker_fd is not None:
        return worker(args.mode, args.worker_fd, args.state_root)
    report = supervise(args.mode, args.state_root)
    print(json.dumps(report, sort_keys=True))
    # A failed previous pass stays visible in cron even as the next pass starts.
    return 2 if report.get('previous_status') in ('FAILED', 'INTERRUPTED') else 0


if __name__ == '__main__':
    raise SystemExit(main())
