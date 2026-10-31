"""Root-only backup settings, Telegram delivery and fixed web-service controls."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import uuid
from vpn import backups

ROOT = Path('/etc/openvpn-panel')
DIRECTORY = Path('/var/lib/openvpn-panel-backups')
FILENAME = re.compile(r'backup-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.ovpnbak\Z')
DEFAULTS = dict(enabled=False, interval=15, token='', chat_id='', passphrase='')


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default.copy()


def atomic_json(path, data):
    tmp = path.with_suffix('.new')
    with tmp.open('w') as out:
        os.chmod(tmp, 0o600)
        json.dump(data, out)
        out.flush()
        os.fsync(out.fileno())
    tmp.replace(path)


@contextmanager
def locked():
    with (ROOT / 'backup.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def settings():
    return {**DEFAULTS, **read_json(ROOT / 'telegram.json', {})}


def files():
    return [dict(name=p.name, size=p.stat().st_size, created=int(p.stat().st_mtime))
            for p in sorted(DIRECTORY.glob('backup-*.ovpnbak'), key=lambda p: p.stat().st_mtime_ns, reverse=True)
            if FILENAME.fullmatch(p.name) and p.is_file() and not p.is_symlink()][:20]


def public_settings():
    cfg = settings()
    return dict(enabled=cfg['enabled'], interval=cfg['interval'], chat_id=cfg['chat_id'],
                token_configured=bool(cfg['token']), encryption_configured=bool(cfg['passphrase']),
                state=read_json(ROOT / 'backup-state.json', {}), files=files())


def save_settings(message):
    if set(message) != {'operation', 'enabled', 'interval', 'token', 'chat_id', 'passphrase'}:
        raise ValueError('Invalid settings fields')
    if type(message['enabled']) is not bool or type(message['interval']) is not int or not 5 <= message['interval'] <= 10080:
        raise ValueError('Interval must be 5-10080 minutes')
    if not all(type(message[k]) is str for k in ('token', 'chat_id', 'passphrase')):
        raise ValueError('Invalid settings types')
    with locked():
        cfg = settings()
        for field in ('token', 'passphrase'):
            if message[field]:
                cfg[field] = message[field]
        cfg.update(enabled=message['enabled'], interval=message['interval'], chat_id=message['chat_id'].strip())
        if cfg['token'] and not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}', cfg['token']):
            raise ValueError('Invalid Telegram bot token')
        if cfg['chat_id'] and not re.fullmatch(r'-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64}', cfg['chat_id']):
            raise ValueError('Invalid Telegram chat ID')
        if cfg['passphrase'] and not 16 <= len(cfg['passphrase']) <= 1024:
            raise ValueError('Backup passphrase must be 16-1024 characters')
        if cfg['enabled'] and not all(cfg[k] for k in ('token', 'chat_id', 'passphrase')):
            raise ValueError('Bot token, chat ID and encryption passphrase are required')
        atomic_json(ROOT / 'telegram.json', cfg)
    return public_settings()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send_telegram(token, chat_id, path):
    """HTTPS only, no redirects, no environment proxy, no token/error body in logs."""
    boundary = 'OVPNPanel' + uuid.uuid4().hex
    payload = path.read_bytes()
    if len(payload) > backups.MAX_ARCHIVE or not payload.startswith(backups.MAGIC):
        raise ValueError('Only bounded encrypted backups may be sent')
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{path.name}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n').encode() + payload + f'\r\n--{boundary}--\r\n'.encode()
    request = urllib.request.Request(f'https://api.telegram.org/bot{token}/sendDocument', data=body,
        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=60) as response:
        raw = response.read(65537)
    if len(raw) > 65536 or json.loads(raw).get('ok') is not True:
        raise ValueError('Telegram delivery failed')


def create_backup(cfg):
    if not cfg['passphrase']:
        raise ValueError('Configure encryption passphrase first')
    # Serialize with certificate issuance/rotation, and every backup/restore.
    with (ROOT / 'pki/lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        encrypted = backups.encrypt(backups.capture(), cfg['passphrase'])
    name = 'backup-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8] + '.ovpnbak'
    target = DIRECTORY / name
    temp = DIRECTORY / (name + '.new')
    try:
        with temp.open('xb') as out:
            os.chmod(temp, 0o640)
            out.write(encrypted)
            out.flush()
            os.fsync(out.fileno())
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)
    for old in sorted(DIRECTORY.glob('backup-*.ovpnbak'), key=lambda p: p.stat().st_mtime_ns, reverse=True)[20:]:
        if FILENAME.fullmatch(old.name):
            old.unlink()
    return target


def run_backup(manual=False):
    with locked():
        cfg = settings()
        state = read_json(ROOT / 'backup-state.json', {})
        now = int(time.time())
        if not manual and (not cfg['enabled'] or now - state.get('last_attempt', 0) < cfg['interval'] * 60):
            return None
        state.update(last_attempt=now, last_error=None)
        atomic_json(ROOT / 'backup-state.json', state)
        try:
            target = create_backup(cfg)
            state.update(last_backup=now, filename=target.name)
            if cfg['enabled']:
                try:
                    send_telegram(cfg['token'], cfg['chat_id'], target)
                    state['last_sent'] = int(time.time())
                    state['sent_filename'] = target.name
                except Exception:
                    state['last_error'] = 'telegram_failed'
        except Exception:
            state['last_error'] = 'backup_failed'
        atomic_json(ROOT / 'backup-state.json', state)
        return public_settings()


def control_web(action):
    if action not in ('restart', 'stop'):
        raise ValueError('Invalid web action')
    # Delay permits the UI to return an acknowledgement before its worker exits.
    subprocess.run(['/usr/bin/systemd-run', '--quiet', '--collect',
        '--unit=openvpn-panel-web-' + uuid.uuid4().hex, '--on-active=3s', '--timer-property=AccuracySec=1s',
        '/usr/local/sbin/openvpn-panelctl', 'web-' + action], check=True,
        capture_output=True, timeout=10)
    return {'scheduled': True}


def dispatch(message):
    operation = message.get('operation')
    if operation in ('network-settings-get','ssl-save','vpn-save','panel-save'):
        from vpn import network_settings
        if operation == 'network-settings-get' and set(message) == {'operation'}:
            return network_settings.public_settings()
        if operation in ('ssl-save','vpn-save','panel-save'):
            return network_settings.queue(message)
        raise ValueError('Invalid network settings fields')
    if operation == 'backup-settings-get' and set(message) == {'operation'}:
        return public_settings()
    if operation == 'backup-settings-save':
        return save_settings(message)
    if operation == 'backup-create' and set(message) == {'operation'}:
        return run_backup(manual=True)
    if operation == 'web-control' and set(message) == {'operation', 'action'}:
        return control_web(message['action'])
    raise ValueError('Unknown operation')
