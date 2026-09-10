#!/usr/bin/env python3
"""Host FIM: explicit immutable baseline, SHA-256 and machine-readable reports.

Exit codes: 0 unchanged/initialized, 1 changes, 2 incomplete check/error.
A baseline from an already exposed host is not proof of a clean installation.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOTS = ['/usr/bin', '/usr/sbin', '/usr/lib', '/usr/lib64', '/usr/libexec', '/usr/local',
         '/bin', '/sbin', '/lib', '/lib64', '/boot', '/etc',
         '/root/.ssh', '/var/spool/cron', '/opt/beeia-security']


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def inventory(roots):
    entries, errors = {}, []

    def visit(path):
        try:
            before = path.lstat()
            item = dict(mode=stat.S_IMODE(before.st_mode), uid=before.st_uid,
                        gid=before.st_gid)
            if stat.S_ISLNK(before.st_mode):
                item.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISDIR(before.st_mode):
                item['kind'] = 'directory'
            elif stat.S_ISREG(before.st_mode):
                digest = hashlib.sha256()
                # Refuse symlink substitution while opening on Linux.
                fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
                with os.fdopen(fd, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        raise OSError('file type changed during scan')
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
                signature = lambda s: (s.st_dev, s.st_ino, s.st_size,
                                       s.st_mtime_ns, s.st_ctime_ns)
                identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
                if (identity(before) != identity(opened)
                        or signature(opened) != signature(after)
                        or identity(after) != identity(path.lstat())):
                    raise OSError('file changed during scan')
                item.update(kind='file', sha256=digest.hexdigest(), size=after.st_size)
            else:
                item['kind'] = 'special'
            entries[str(path)] = item
            if item['kind'] == 'directory':
                for child in sorted(path.iterdir()):
                    visit(child)
        except OSError as exc:
            errors.append(dict(path=str(path), error=str(exc)))

    for root in roots:
        path = Path(root)
        try:
            path.lstat()
        except FileNotFoundError:
            entries[str(path)] = {'kind': 'absent'}
        except OSError as exc:
            errors.append(dict(path=str(path), error=str(exc)))
        else:
            visit(path)
    return entries, errors


def write_json(path, data, exclusive=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, sort_keys=True) + '\n'
    if exclusive:
        # O_EXCL prevents accidental acceptance/replacement of an old baseline.
        with path.open('x', encoding='utf-8') as stream:
            stream.write(content)
    else:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix='.fim-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(content)
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'check'])
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/beeia-integrity'))
    parser.add_argument('--root', action='append', help='Custom roots (init only; tests)')
    args = parser.parse_args()
    os.umask(0o077)
    baseline = args.state_dir / 'baseline.json'
    if args.action == 'init':
        if baseline.exists():
            raise ValueError('Baseline already exists; review and archive it before reinitializing')
        roots = args.root or ROOTS + [str(p / '.ssh') for p in Path('/home').glob('*') if p.is_dir()]
        roots = sorted(set(os.path.abspath(p) for p in roots))
        entries, errors = inventory(roots)
        if errors:
            raise ValueError('Incomplete baseline: ' + json.dumps(errors))
        write_json(baseline, dict(schema=1, created_at=now(), roots=roots,
                                 entries=entries, provenance='current-host-not-installation'), True)
        print(f'Baseline created: {baseline}; entries={len(entries)}; not proof of a clean host')
        return 0
    if args.root:
        raise ValueError('--root is only accepted for init')
    raw = baseline.read_bytes()
    saved = json.loads(raw)
    if saved.get('schema') != 1 or not saved.get('roots') or not saved.get('entries'):
        raise ValueError('Invalid or empty baseline')
    current, errors = inventory(saved['roots'])
    old = saved['entries']
    changes = {kind: sorted(paths) for kind, paths in {
        'added': current.keys() - old.keys(),
        'removed': old.keys() - current.keys(),
        'modified': {p for p in current.keys() & old.keys() if current[p] != old[p]},
    }.items()}
    status = 'error' if errors else ('changed' if any(changes.values()) else 'unchanged')
    report = dict(checked_at=now(), status=status, baseline_created_at=saved['created_at'],
                  baseline_sha256=hashlib.sha256(raw).hexdigest(), changes=changes, errors=errors,
                  entries=len(current))
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    write_json(args.state_dir / 'reports' / (stamp + '.json'), report, True)
    write_json(args.state_dir / 'latest.json', report)
    print(json.dumps(report))
    return 2 if errors else (1 if status == 'changed' else 0)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'FIM ERROR: {exc}', file=sys.stderr)
        sys.exit(2)
