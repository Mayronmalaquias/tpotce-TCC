#!/usr/bin/env python3
"""BeeIA: private S3 backups with restore verification, SNS alerts, heartbeat.

Uses the VM instance role, never static AWS access keys. Configuration is stored
in /etc/beeia-security/operations.json. Backups exclude secrets and malware.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def aws(config, *args):
    environment = dict(os.environ, AWS_PAGER='', AWS_CLI_AUTO_PROMPT='off')
    result = subprocess.run(
        [config.get('aws_cli', '/usr/bin/aws'), '--region', config['region'],
         '--no-cli-pager', '--output', 'json', *args],
        capture_output=True, text=True, timeout=600, env=environment)
    if result.returncode:
        # Never include request data/credentials or arbitrary service output in email.
        raise RuntimeError(f'AWS {args[0]} {args[1]} failed (exit {result.returncode})')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def publish(config, subject, message):
    return aws(config, 'sns', 'publish', '--topic-arn', config['topic_arn'],
               '--subject', subject[:100], '--message', message)


EXCLUDED_PARTS = {'venv', '.venv', '__pycache__', 'node_modules', '.git',
                  'downloads', 'binaries', 'cert', 'certs', '.ssh', '.aws'}


def copy_tree(source, destination):
    """Explicit source roots only, no symlinks, devices, credentials or malware."""
    source, destination = Path(source), Path(destination)
    if source.is_symlink():
        raise ValueError('Backup source root is a symlink')
    if not source.exists():
        return
    for current, directories, filenames in os.walk(source, followlinks=False):
        directories[:] = [n for n in directories if n not in EXCLUDED_PARTS
                           and not (Path(current) / n).is_symlink()]
        for name in filenames:
            path = Path(current) / name
            if (path.is_symlink() or not path.is_file() or name == '.env'
                    or name.startswith('.env.') or name.endswith(('.pem', '.key', '.p12', '.pfx', '.pyc'))
                    or name in ('credentials', 'nginxpasswd', 'lswebpasswd')):
                continue
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, target)
            target.chmod(0o600)


def build_archive(project, integrity, target):
    project, integrity, target = Path(project), Path(integrity), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='capture-', dir=target.parent) as directory:
        staging = Path(directory)
        database = staging / 'database/beeia.db'
        database.parent.mkdir()
        with sqlite3.connect('file:' + str(project / 'data/beeia.db') + '?mode=ro', uri=True) as live:
            with sqlite3.connect(database) as snapshot:
                live.backup(snapshot)
                if snapshot.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('Database consistency check failed')
                rows = snapshot.execute('SELECT count(*) FROM attacks').fetchone()[0]
        for folder in ['backend', 'frontend/src', 'scripts', 'ml/cowrie/models', 'ml/dionaea/models',
                       'data/cowrie/log', 'data/dionaea/log']:
            copy_tree(project / folder, staging / 'project' / folder)
        for name in ['docker-compose.yml', 'frontend/package.json', 'frontend/package-lock.json',
                     'frontend/index.html', 'frontend/tailwind.config.js',
                     'docker/nginx/dist/conf/beeia.conf']:
            source = project / name
            if source.is_file() and not source.is_symlink():
                destination = staging / 'project' / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        copy_tree(integrity, staging / 'integrity')
        manifest = {
            'schema': 1, 'created_at': utcnow().isoformat(), 'database_rows': rows,
            'limitations': 'SQLite is consistent; live logs are copied over an interval. Secrets and malware excluded.',
            'sha256': {str(p.relative_to(staging).as_posix()): sha256(p)
                       for p in staging.rglob('*') if p.is_file()},
        }
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        with tarfile.open(target, 'w:gz') as archive:
            for file in sorted(staging.rglob('*')):
                if file.is_file():
                    archive.add(file, arcname=file.relative_to(staging).as_posix(), recursive=False)
        target.chmod(0o600)
        if target.stat().st_size > 4 * 1024 ** 3:
            raise ValueError('Backup exceeds single-upload limit; review retention and multipart design')
        return manifest


def verify_archive(archive_path, destination):
    """Restore only into an empty temporary directory; never execute restored code."""
    destination = Path(destination)
    if not destination.is_dir() or any(destination.iterdir()):
        raise ValueError('Restore verification requires an empty directory')
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or '..' in path.parts
                    or '\\' in member.name or ':' in member.name or member.name in names):
                raise ValueError('Unsafe or duplicate archive member')
            names.add(member.name)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
    manifest = json.loads((destination / 'manifest.json').read_text())
    if names != set(manifest['sha256']) | {'manifest.json'}:
        raise ValueError('Manifest does not match archive inventory')
    for name, expected in manifest['sha256'].items():
        if sha256(destination / name) != expected:
            raise ValueError('Restored file checksum mismatch')
    with sqlite3.connect('file:' + str(destination / 'database/beeia.db') + '?mode=ro', uri=True) as db:
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Restored database failed consistency check')
        if db.execute('SELECT count(*) FROM attacks').fetchone()[0] != manifest['database_rows']:
            raise ValueError('Restored database row count mismatch')
    return manifest


def backup(config, state):
    started = utcnow()
    backup_dir = state / 'backups'
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = started.strftime('%Y%m%dT%H%M%S%fZ')
    path = backup_dir / ('backup-' + stamp + '.tar.gz')
    manifest = build_archive(config['project'], config['integrity_state'], path)
    digest = sha256(path)
    key = config['instance_id'] + '/' + started.strftime('%Y/%m/%d/') + path.name
    uploaded = aws(config, 's3api', 'put-object', '--bucket', config['bucket'], '--key', key,
                   '--body', str(path), '--server-side-encryption', 'AES256',
                   '--checksum-algorithm', 'SHA256', '--if-none-match', '*')
    version = uploaded.get('VersionId')
    if not version:
        raise ValueError('S3 version ID missing; versioning must be enabled')
    with tempfile.TemporaryDirectory(prefix='restore-', dir=state) as directory:
        downloaded = Path(directory) / 'download.tar.gz'
        aws(config, 's3api', 'get-object', '--bucket', config['bucket'], '--key', key,
            '--version-id', version, str(downloaded))
        if sha256(downloaded) != digest:
            raise ValueError('Downloaded backup checksum mismatch')
        restored = Path(directory) / 'restored'
        restored.mkdir()
        verify_archive(downloaded, restored)
    report = {'status': 'ok', 'started_at': started.isoformat(), 'completed_at': utcnow().isoformat(),
              'bucket': config['bucket'], 'key': key, 'version_id': version,
              'sha256': digest, 'bytes': path.stat().st_size,
              'database_rows': manifest['database_rows'], 'restore_verified': True}
    atomic_json(state / 'backup-latest.json', report)
    atomic_json(backup_dir / (stamp + '.json'), report)
    # Only remove older local archives after external upload AND restore passed.
    for old in sorted(backup_dir.glob('backup-*.tar.gz'))[:-3]:
        if old.is_file() and not old.is_symlink():
            old.unlink()
    print(json.dumps(report))


def report_problems(integrity, backup_report, now):
    problems = []
    for name, report, timestamp, max_hours in [
        ('integrity', integrity, 'checked_at', 2), ('backup', backup_report, 'completed_at', 26)
    ]:
        try:
            age = (now - dt.datetime.fromisoformat(report[timestamp].replace('Z', '+00:00'))).total_seconds()
            if age < -300 or age > max_hours * 3600:
                problems.append(name + '_stale')
        except (KeyError, TypeError, ValueError):
            problems.append(name + '_missing_or_invalid')
        expected = 'unchanged' if name == 'integrity' else 'ok'
        if report.get('status') != expected:
            problems.append(name + '_not_ok')
    if backup_report.get('restore_verified') is not True:
        problems.append('backup_restore_not_verified')
    return problems


def read_report(path):
    try:
        result = json.loads(Path(path).read_text())
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def watchdog(config, state):
    now = utcnow()
    problems = report_problems(read_report(Path(config['integrity_state']) / 'latest.json'),
                               read_report(state / 'backup-latest.json'), now)
    for unit in ['beeia-integrity.timer', 'beeia-backup.timer', 'beeia-containment.service',
                 'beeia-backend.service']:
        if subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode:
            problems.append(unit + '_inactive')
    for unit in ['beeia-integrity.service', 'beeia-backup.service']:
        result = subprocess.run(['systemctl', 'show', unit, '-p', 'Result', '--value'],
                                capture_output=True, text=True)
        if result.returncode or result.stdout.strip() != 'success':
            problems.append(unit + '_failed')
    check = subprocess.run(['/usr/bin/python3', '/opt/beeia-security/honeypot_firewall.py', 'check'],
                           capture_output=True, timeout=60)
    if check.returncode:
        problems.append('containment_check_failed')
    disk = shutil.disk_usage(state)
    if disk.free < max(disk.total * 0.10, 512 * 1024 ** 2):
        problems.append('disk_space_low')
    previous = read_report(state / 'watchdog-latest.json')
    signature = hashlib.sha256(json.dumps(sorted(problems)).encode()).hexdigest()
    last_sent = previous.get('last_sent_at')
    reminder_due = not last_sent or (now - dt.datetime.fromisoformat(last_sent)).total_seconds() > 21600
    if (problems and (previous.get('signature') != signature or reminder_due)) or (
            not problems and previous.get('problems')):
        publish(config, 'BeeIA: ' + ('alerta de seguranca' if problems else 'monitoramento recuperado'),
                'Host ' + config['instance_id'] + '\nUTC: ' + now.isoformat() + '\n' +
                ('Problemas: ' + ', '.join(problems) if problems else 'Os testes operacionais voltaram ao estado esperado.') +
                '\nConsulte o journal e os relatorios na VM. Esta mensagem nao atesta ausencia de invasao.')
        last_sent = now.isoformat()
    # The alarm lives outside the VM and treats missing metrics as a failure.
    aws(config, 'cloudwatch', 'put-metric-data', '--namespace', 'BeeIA/Security',
        '--metric-data', json.dumps([{'MetricName': 'Heartbeat', 'Value': 1, 'Unit': 'Count',
                                    'Dimensions': [{'Name': 'InstanceId', 'Value': config['instance_id']}]}]))
    report = {'checked_at': now.isoformat(), 'problems': problems, 'signature': signature,
              'last_sent_at': last_sent, 'heartbeat_sent': True}
    atomic_json(state / 'watchdog-latest.json', report)
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backup', 'watch', 'notify-failure', 'test-alert'])
    parser.add_argument('--config', type=Path, default=Path('/etc/beeia-security/operations.json'))
    parser.add_argument('--unit', default='beeia-security')
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    state = Path(config.get('state_dir', '/var/lib/beeia-ops'))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        if args.action == 'backup':
            backup(config, state)
        elif args.action == 'watch':
            watchdog(config, state)
        else:
            test = args.action == 'test-alert'
            publish(config, 'BeeIA: ' + ('teste de notificacao' if test else 'falha de servico'),
                    ('Teste solicitado de entrega dos alertas de seguranca e backup.' if test else
                     'Falha no servico ' + args.unit + '. Consulte o journal da VM.') +
                    '\nHost: ' + config['instance_id'] + '\nUTC: ' + utcnow().isoformat())
            print('Notification accepted by SNS; delivery requires confirmed email subscriptions')
    except Exception as exc:
        if args.action == 'backup':
            atomic_json(state / 'backup-latest.json', {'status': 'error', 'failed_at': utcnow().isoformat(),
                                                      'error_type': type(exc).__name__})
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('SECURITY OPERATIONS ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(2)
