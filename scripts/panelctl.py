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
import sys
import time
sys.path.insert(0, '/opt/openvpn-panel')
from vpn import backups
from werkzeug.security import generate_password_hash


def systemctl(*args):
    subprocess.run(['systemctl', *args], check=True)


def wait_accounting():
    deadline = time.monotonic() + 20
    heartbeat = Path('/run/openvpn-panel/heartbeat')
    while time.monotonic() < deadline:
        try:
            if 0 <= time.time() - heartbeat.stat().st_mtime <= 10:
                return
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    raise RuntimeError('Accounting heartbeat not ready; OpenVPN must remain fail-closed')


def restart():
    # Explicit ordering avoids a collector EOF racing a new server process.
    systemctl('stop', 'openvpn-server@panel.service')
    systemctl('stop', 'openvpn-panel-accounting.service')
    systemctl('reset-failed', 'openvpn-panel.service', 'openvpn-panel-pki.service', 'openvpn-panel-accounting.service', 'openvpn-server@panel.service')
    systemctl('start', 'openvpn-server@panel.service')
    wait_accounting()
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


def passphrase(path=None):
    if path:
        import stat
        file = Path(path)
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Passphrase file must be root-owned regular file, mode 0600')
        return file.read_text().rstrip('\r\n')
    return getpass.getpass('Backup encryption passphrase (16+ characters): ')


def backup(destination, encrypted=False, password_file=None):
    with Path('/etc/openvpn-panel/pki/lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = backups.capture()
    if encrypted:
        data = backups.encrypt(data, passphrase(password_file))
    with Path(destination).open('xb') as output:
        os.chmod(destination, 0o600)
        output.write(data)
    print('Backup created. Keep it private; encrypted backups require the original passphrase.')


def restore(source, password_file=None, yes=False):
    path = Path(source)
    if not path.is_file() or path.stat().st_size > backups.MAX_ARCHIVE:
        raise ValueError('Invalid or oversized backup')
    data = path.read_bytes()
    if data.startswith(backups.MAGIC):
        data = backups.decrypt(data, passphrase(password_file))
    if not yes and input('Replace users and VPN keys on THIS server? Type RESTORE: ') != 'RESTORE':
        raise ValueError('Restore cancelled')
    with tempfile.TemporaryDirectory(prefix='panel-restore-') as temp:
        stage = Path(temp)
        backups.validate_archive(data, stage)  # Before stopping anything.
        with Path('/etc/openvpn-panel/backup.lock').open('a') as maintenance:
            fcntl.flock(maintenance, fcntl.LOCK_EX)
            timer_active = subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-panel-backup.timer']).returncode == 0
            systemctl('stop', 'openvpn-panel-backup.timer', 'openvpn-panel-backup.service')
            systemctl('stop', 'openvpn-server@panel', 'openvpn-panel-accounting', 'openvpn-panel', 'openvpn-panel-pki')
            def activate():
                systemctl('reset-failed', 'openvpn-panel.service', 'openvpn-panel-pki.service', 'openvpn-panel-accounting.service', 'openvpn-server@panel.service')
                systemctl('start', 'openvpn-panel-pki', 'openvpn-panel')
                systemctl('start', 'openvpn-server@panel')
                wait_accounting()
                for unit in ('openvpn-panel-pki', 'openvpn-panel', 'openvpn-server@panel', 'openvpn-panel-accounting'):
                    systemctl('is-active', '--quiet', unit)
            try:
                safety_dir = Path('/var/backups/openvpn-panel')
                safety_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                safety = safety_dir / ('pre-restore-' + str(time.time_ns()) + '.tar.gz')
                backup(safety)
                print('Local private rollback snapshot:', safety)
                backups.apply_restore(stage, activate=activate, deactivate=lambda: systemctl('stop', 'openvpn-server@panel', 'openvpn-panel-accounting', 'openvpn-panel', 'openvpn-panel-pki'))
            except BaseException:
                # apply_restore has already put original files back before this.
                systemctl('stop', 'openvpn-server@panel', 'openvpn-panel-accounting', 'openvpn-panel', 'openvpn-panel-pki')
                activate()
                raise
            finally:
                if timer_active:
                    systemctl('start', 'openvpn-panel-backup.timer')
    print('Restore complete. New server endpoint, domain, admin password and Telegram settings were preserved.')
    print('Old VPN files need the new endpoint unless you move the original VPN DNS record.')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo.')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'restart', 'password', 'backup', 'restore', 'web-start', 'web-stop', 'web-restart'])
    parser.add_argument('destination', nargs='?')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt backup with AES-256-GCM')
    parser.add_argument('--passphrase-file', help='Root-owned 0600 file (otherwise prompts)')
    parser.add_argument('--yes', action='store_true', help='Confirm destructive restore')
    args = parser.parse_args()
    if args.action == 'status':
        systemctl('status', '--no-pager', 'openvpn-panel', 'openvpn-panel-pki',
                  'openvpn-panel-accounting', 'openvpn-server@panel')
    elif args.action == 'restart':
        restart()
    elif args.action == 'password':
        password()
    elif args.action.startswith('web-'):
        action = args.action.split('-')[1]
        if action in ('start', 'restart'):
            systemctl('reset-failed', 'openvpn-panel.service')
        systemctl(action, 'openvpn-panel.service')
    elif not args.destination:
        parser.error('backup requires an output path (must not already exist)')
    elif args.action == 'restore':
        restore(args.destination, args.passphrase_file, args.yes)
    else:
        backup(args.destination, args.encrypt, args.passphrase_file)


if __name__ == '__main__':
    main()
