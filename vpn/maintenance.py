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
import urllib.error
import socket
import ssl
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
            for p in sorted(DIRECTORY.glob('backup-*.ovpnbak'), key=lambda p: (p.stat().st_mtime_ns,p.name), reverse=True)
            if FILENAME.fullmatch(p.name) and p.is_file() and not p.is_symlink()][:20]


def public_settings():
    cfg = settings()
    return dict(enabled=cfg['enabled'], interval=cfg['interval'], chat_id=cfg['chat_id'],
                token_configured=bool(cfg['token']), telegram_configured=bool(cfg['token'] and cfg['chat_id']), encryption_configured=False,
                state=read_json(ROOT / 'backup-state.json', {}), files=files(),
                restore=read_json(ROOT/'restore-state.json',{}))


def save_settings(message):
    if set(message) not in ({'operation','enabled','interval','token','chat_id'}, {'operation','enabled','interval','token','chat_id','passphrase'}):
        raise ValueError('Invalid settings fields')
    if type(message['enabled']) is not bool or type(message['interval']) is not int or not 5 <= message['interval'] <= 10080:
        raise ValueError('Interval must be 5-10080 minutes')
    if not all(type(message[k]) is str for k in ('token', 'chat_id')):
        raise ValueError('Invalid settings types')
    with locked():
        cfg = settings()
        for field in ('token',):
            if message[field]:
                cfg[field] = message[field]
        cfg.update(enabled=message['enabled'], interval=message['interval'], chat_id=message['chat_id'].strip())
        if cfg['token'] and not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}', cfg['token']):
            raise ValueError('Invalid Telegram bot token')
        if cfg['chat_id'] and not re.fullmatch(r'-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64}', cfg['chat_id']):
            raise ValueError('Invalid Telegram chat ID')
        cfg.pop('passphrase',None)
        if cfg['enabled'] and not all(cfg[k] for k in ('token', 'chat_id')):
            raise ValueError('Bot token and chat ID are required')
        atomic_json(ROOT / 'telegram.json', cfg)
    return public_settings()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class TelegramFailure(ValueError):
    """Only stable allowlisted codes may cross the privileged boundary."""
    def __init__(self, code, retry_after=None):
        self.code, self.retry_after = code, retry_after
        super().__init__(code)


def telegram_failure(status, raw=b''):
    info = {}
    try:
        if len(raw) <= 65536:
            parsed = json.loads(raw)
            if isinstance(parsed,dict): info = parsed
    except (ValueError,UnicodeError): pass
    description = info.get('description','')
    description = description.lower() if isinstance(description,str) else ''
    retry = info.get('parameters',{})
    retry = retry.get('retry_after') if isinstance(retry,dict) else None
    retry = retry if type(retry) is int and 1 <= retry <= 86400 else None
    if status == 429: return TelegramFailure('rate_limited',retry)
    if status in (401,404): return TelegramFailure('invalid_token')
    if status == 413: return TelegramFailure('file_too_large')
    if status == 403:
        return TelegramFailure('bot_blocked' if 'blocked' in description else 'permission_denied')
    if status == 400:
        if 'chat not found' in description: return TelegramFailure('chat_not_found')
        if 'migrat' in description or ('supergroup' in description and 'upgrad' in description):
            return TelegramFailure('chat_migrated')
        if any(word in description for word in ('rights','permission','not a member','kicked')):
            return TelegramFailure('permission_denied')
        return TelegramFailure('invalid_request')
    if type(status) is int and 500 <= status <= 599: return TelegramFailure('telegram_unavailable')
    return TelegramFailure('invalid_response')


def send_telegram(token, chat_id, path):
    """HTTPS only, no redirects, no environment proxy, no token/error body in logs."""
    boundary = 'OVPNPanel' + uuid.uuid4().hex
    payload = path.read_bytes()
    if len(payload) > backups.MAX_ARCHIVE or not payload.startswith((b'\x1f\x8b',backups.MAGIC)):
        raise ValueError('Only bounded backup archives may be sent')
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{path.name}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n').encode() + payload + f'\r\n--{boundary}--\r\n'.encode()
    request = urllib.request.Request(f'https://api.telegram.org/bot{token}/sendDocument', data=body,
        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        try: raw = error.read(65537)
        except OSError: raw = b''
        finally: error.close()
        raise telegram_failure(error.code,raw) from None
    except urllib.error.URLError as error:
        reason = error.reason
        code = ('tls_error' if isinstance(reason,ssl.SSLError) else
                'dns_error' if isinstance(reason,socket.gaierror) else
                'timeout' if isinstance(reason,TimeoutError) else 'network_error')
        raise TelegramFailure(code) from None
    except (TimeoutError,socket.timeout): raise TelegramFailure('timeout') from None
    except ssl.SSLError: raise TelegramFailure('tls_error') from None
    except OSError: raise TelegramFailure('network_error') from None
    try:
        if len(raw) > 65536: raise TelegramFailure('invalid_response')
        result = json.loads(raw)
        if not isinstance(result,dict): raise TelegramFailure('invalid_response')
        if result.get('ok') is not True:
            raise telegram_failure(result.get('error_code'),raw)
    except (json.JSONDecodeError,UnicodeError):
        raise TelegramFailure('invalid_response') from None


def create_backup(cfg):
    # Serialize with certificate issuance/rotation, and every backup/restore.
    with (ROOT / 'pki/lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        payload = backups.capture()
    name = 'backup-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8] + '.ovpnbak'
    target = DIRECTORY / name
    temp = DIRECTORY / (name + '.new')
    try:
        with temp.open('xb') as out:
            os.chmod(temp, 0o640)
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)
    previous = [p for p in DIRECTORY.glob('backup-*.ovpnbak') if p != target]
    for old in sorted(previous, key=lambda p: (p.stat().st_mtime_ns,p.name), reverse=True)[19:]:
        if FILENAME.fullmatch(old.name):
            old.unlink()
    return target


def run_backup(manual=False, send_now=False):
    with locked():
        cfg = settings()
        state = read_json(ROOT / 'backup-state.json', {})
        now = int(time.time())
        if not manual and (not cfg['enabled'] or now - state.get('last_attempt', 0) < cfg['interval'] * 60):
            return None
        state.update(last_attempt=now, last_error=None, telegram_error=None, retry_after=None, telegram_status='not_attempted')
        atomic_json(ROOT / 'backup-state.json', state)
        try:
            target = create_backup(cfg)
            state.update(last_backup=now, filename=target.name)
            if cfg['enabled'] or send_now:
                state['telegram_status']='sending'
                atomic_json(ROOT/'backup-state.json',state)
                try:
                    if not cfg['token'] or not cfg['chat_id']: raise TelegramFailure('not_configured')
                    send_telegram(cfg['token'], cfg['chat_id'], target)
                    state['last_sent'] = int(time.time())
                    state['sent_filename'] = target.name
                    state['telegram_status']='sent'
                except TelegramFailure as error:
                    state.update(last_error='telegram_failed',telegram_status='failed',telegram_error=error.code,retry_after=error.retry_after)
                except Exception:
                    state.update(last_error='telegram_failed',telegram_status='failed',telegram_error='unexpected')
            else:
                state['telegram_status']='skipped'
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
    if operation == 'backup-restore-status' and set(message) == {'operation'}:
        from vpn.web_restore import status
        return status()
    if operation == 'backup-settings-get' and set(message) == {'operation'}:
        return public_settings()
    if operation == 'backup-settings-save':
        return save_settings(message)
    if operation == 'backup-create' and set(message) in ({'operation'},{'operation','send_now'}):
        if type(message.get('send_now',False)) is not bool: raise ValueError('Invalid send flag')
        return run_backup(manual=True,send_now=message.get('send_now',False))
    if operation == 'web-control' and set(message) == {'operation', 'action'}:
        return control_web(message['action'])
    raise ValueError('Unknown operation')
