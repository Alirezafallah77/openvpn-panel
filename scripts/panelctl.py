#!/opt/openvpn-panel/.venv/bin/python
"""Root-only maintenance. Never pass secrets as command-line arguments."""
import argparse
import fcntl
import getpass
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile
from werkzeug.security import generate_password_hash


def systemctl(*args):
    subprocess.run(['systemctl', *args], check=True)


def restart():
    # Explicit ordering avoids a collector EOF racing a new server process.
    systemctl('stop', 'openvpn-server@panel.service')
    systemctl('stop', 'openvpn-panel-accounting.service')
    systemctl('start', 'openvpn-server@panel.service')
    systemctl('restart', 'openvpn-panel.service', 'openvpn-panel-pki.service')


def password():
    while True:
        new = getpass.getpass('New admin password (12+ characters): ')
        repeat = getpass.getpass('Repeat password: ')
        if len(new) >= 12 and new == repeat:
            break
        print('Passwords must match, minimum 12 characters.')
    path = Path('/etc/openvpn-panel/panel.env')
    lines = path.read_text().splitlines()
    lines = [line for line in lines if not line.startswith(('PANEL_PASSWORD_HASH=', 'PANEL_SECRET='))]
    lines.extend(["PANEL_PASSWORD_HASH='" + generate_password_hash(new) + "'",
                  'PANEL_SECRET=' + secrets.token_urlsafe(48)])
    tmp = path.with_suffix('.new')
    tmp.write_text('\n'.join(lines) + '\n')
    tmp.chmod(0o600)
    tmp.replace(path)
    systemctl('restart', 'openvpn-panel.service')
    print('Password changed and previous admin sessions invalidated.')


def backup(destination):
    target = Path(destination).absolute()
    # Exclusive creation prevents accidental replacement and symlink overwrites.
    with target.open('xb') as output, tempfile.TemporaryDirectory(prefix='panel-backup-') as tmp:
        with Path('/etc/openvpn-panel/pki/lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            snap = Path(tmp) / 'quota.sqlite'
            with sqlite3.connect('file:/var/lib/openvpn-panel/quota.sqlite?mode=ro', uri=True) as source:
                with sqlite3.connect(snap) as dest:
                    source.backup(dest)
                    assert dest.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                archive.add('/etc/openvpn-panel', arcname='etc/openvpn-panel')
                archive.add('/etc/openvpn/server/panel.conf', arcname='etc/openvpn/server/panel.conf')
                archive.add(snap, arcname='var/lib/openvpn-panel/quota.sqlite')
    print('Backup created mode 0600. Contains CA and client private keys; encrypt off-server storage.')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo.')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'restart', 'password', 'backup'])
    parser.add_argument('destination', nargs='?')
    args = parser.parse_args()
    if args.action == 'status':
        systemctl('status', '--no-pager', 'openvpn-panel', 'openvpn-panel-pki',
                  'openvpn-panel-accounting', 'openvpn-server@panel')
    elif args.action == 'restart':
        restart()
    elif args.action == 'password':
        password()
    elif not args.destination:
        parser.error('backup requires an output path (must not already exist)')
    else:
        backup(args.destination)


if __name__ == '__main__':
    main()
