"""Bounded, authenticated migration backups; never extract untrusted tar paths."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'OVPNPANEL-BACKUP-1\0'
MAX_ARCHIVE = 45 * 1024**2
MAX_EXPANDED = 256 * 1024**2
ROOT = Path('/etc/openvpn-panel')
DATABASE = Path('/var/lib/openvpn-panel/quota.sqlite')
BACKUP_DIR = Path('/var/lib/openvpn-panel-backups')


def key(password, salt):
    if not isinstance(password, str) or len(password) < 16 or len(password) > 1024:
        raise ValueError('Backup passphrase must be 16-1024 characters')
    return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1,
                          maxmem=128 * 1024**2, dklen=32)


def encrypt(data, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    result = header + AESGCM(key(password, salt)).encrypt(nonce, data, header)
    if len(result) > MAX_ARCHIVE:
        raise ValueError('Backup exceeds 45 MiB limit')
    return result


def decrypt(data, password):
    if len(data) > MAX_ARCHIVE or not data.startswith(MAGIC) or len(data) < len(MAGIC)+44:
        raise ValueError('Invalid encrypted backup')
    offset = len(MAGIC)
    salt, nonce = data[offset:offset+16], data[offset+16:offset+28]
    header = data[:offset+28]
    try:
        return AESGCM(key(password, salt)).decrypt(nonce, data[offset+28:], header)
    except Exception:
        raise ValueError('Wrong passphrase or corrupted backup') from None


def capture(root=ROOT, database=DATABASE):
    """Caller holds the PKI lock. SQLite backup is transactionally consistent."""
    buffer = io.BytesIO()
    with tempfile.TemporaryDirectory(prefix='panel-snapshot-') as temp:
        snapshot = Path(temp) / 'quota.sqlite'
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as source:
            with sqlite3.connect(snapshot) as dest:
                source.backup(dest)
                if dest.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Database integrity failed')
        total = snapshot.stat().st_size
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            manifest = json.dumps({'format': 2, 'created_at': int(time.time())}).encode()
            info = tarfile.TarInfo('manifest.json')
            info.size, info.mode = len(manifest), 0o600
            archive.addfile(info, io.BytesIO(manifest))
            archive.add(snapshot, arcname='var/lib/openvpn-panel/quota.sqlite', recursive=False)
            for path in sorted(root.rglob('*')):
                relative = path.relative_to(root)
                if relative.parts[0] not in ('pki', 'crl.pem', 'tls-crypt.key'):
                    continue
                if path.is_symlink():
                    raise ValueError('PKI symlinks not allowed')
                if path.is_file():
                    total += path.stat().st_size
                    if total > MAX_EXPANDED:
                        raise ValueError('Expanded backup too large')
                    archive.add(path, arcname='etc/openvpn-panel/' + relative.as_posix(), recursive=False)
    data = buffer.getvalue()
    if len(data) > MAX_ARCHIVE - 128:
        raise ValueError('Backup too large')
    return data


def validate_archive(data, stage):
    if len(data) > MAX_ARCHIVE:
        raise ValueError('Archive too large')
    total, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        count = 0
        for member in archive:
            count += 1
            name = member.name
            path = PurePosixPath(name)
            if (count > 20000 or path.is_absolute() or '..' in path.parts or
                    '\\' in name or name in seen or str(path) != name):
                raise ValueError('Unsafe archive member')
            seen.add(name)
            if member.isdir():
                continue
            if not member.isfile() or member.size < 0:
                raise ValueError('Links/devices are forbidden')
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError('Expanded archive too large')
            approved = (name in ('manifest.json', 'var/lib/openvpn-panel/quota.sqlite',
                'etc/openvpn-panel/crl.pem', 'etc/openvpn-panel/tls-crypt.key') or
                re.fullmatch(r'etc/openvpn-panel/pki/(?:newcerts/)?[A-Za-z0-9_.-]{1,128}', name))
            # Legacy v0.1 backups include host settings; intentionally never restore them.
            legacy = name in ('etc/openvpn-panel/panel.env', 'etc/openvpn-panel/vpn.json',
                              'etc/openvpn/server/panel.conf')
            if not approved and not legacy:
                raise ValueError('Unexpected archive member')
            if approved:
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as source, target.open('xb') as out:
                    shutil.copyfileobj(source, out)
                target.chmod(0o600)
    manifest = stage / 'manifest.json'
    if manifest.exists() and json.loads(manifest.read_text()).get('format') != 2:
        raise ValueError('Unsupported backup version')
    db_path = stage / 'var/lib/openvpn-panel/quota.sqlite'
    with sqlite3.connect(f'file:{db_path}?mode=rw', uri=True) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Invalid SQLite backup')
        if db.execute("SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
            raise ValueError('Unexpected database objects')
        for row in db.execute('SELECT name,limit_bytes,days,used_bytes,enabled,token_hash,first_connected FROM users'):
            name, volume, days, used, enabled, digest, first = row
            if (not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) or type(volume) is not int or volume <= 0 or
                type(days) is not int or days <= 0 or type(used) is not int or used < 0 or enabled not in (0, 1) or
                not re.fullmatch(r'[a-f0-9]{64}', digest) or (first is not None and (type(first) is not int or first < 0))):
                raise ValueError('Invalid user data')
        db.execute('UPDATE sessions SET closed=1')
    pki = stage / 'etc/openvpn-panel/pki'
    for required in ('ca.key', 'ca.crt', 'server.key', 'server.crt', 'index.txt', 'serial', 'crlnumber'):
        if not (pki / required).is_file():
            raise ValueError('Missing PKI file')
    for line in (pki / 'index.txt').read_text().splitlines():
        fields = line.split('\t')
        if len(fields) != 6 or not re.fullmatch(r'[0-9A-Fa-f]+', fields[3]):
            raise ValueError('Invalid CA index')
    for name in ('serial', 'crlnumber'):
        if not re.fullmatch(r'[0-9a-fA-F]+\s*', (pki / name).read_text()):
            raise ValueError('Invalid CA serial')
    def openssl(*args):
        return subprocess.run(['openssl', *args], check=True, capture_output=True, timeout=20).stdout
    for stem in ('ca', 'server'):
        public = openssl('pkey', '-in', str(pki / (stem+'.key')), '-pubout')
        if public != openssl('x509', '-in', str(pki / (stem+'.crt')), '-pubkey', '-noout'):
            raise ValueError('Certificate/key mismatch')
    openssl('verify', '-CAfile', str(pki / 'ca.crt'), str(pki / 'server.crt'))
    openssl('crl', '-in', str(stage / 'etc/openvpn-panel/crl.pem'), '-CAfile', str(pki / 'ca.crt'), '-verify', '-noout')
    tls = (stage / 'etc/openvpn-panel/tls-crypt.key').read_text()
    if '-----BEGIN OpenVPN Static key V1-----' not in tls:
        raise ValueError('Invalid tls-crypt key')
    return pki, db_path


def apply_restore(stage, root=ROOT, database=DATABASE, activate=lambda: None, deactivate=lambda: None):
    """All writers must be stopped. Local rollback on file/startup errors."""
    imported = stage / 'etc/openvpn-panel'
    # Never import OpenSSL config from an archive (engine/provider directives).
    (imported / 'pki/openssl.cnf').write_bytes((root / 'pki/openssl.cnf').read_bytes())
    (imported / 'pki/newcerts').mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='panel-rollback-', dir=root.parent) as temp:
        rollback = Path(temp)
        items = [(root/'pki', imported/'pki'), (root/'crl.pem', imported/'crl.pem'),
                 (root/'tls-crypt.key', imported/'tls-crypt.key'),
                 (database, stage/'var/lib/openvpn-panel/quota.sqlite')]
        saved = []
        try:
            for i, (target, source) in enumerate(items):
                old = rollback / str(i)
                if target.is_dir():
                    shutil.copytree(target, old)
                else:
                    shutil.copy2(target, old)
                saved.append((target, old))
                if target.is_dir():
                    shutil.rmtree(target)
                    shutil.copytree(source, target)
                else:
                    shutil.copyfile(source, target)
                    target.chmod(0o660 if target == database else 0o600)
            activate()
        except BaseException:
            deactivate()
            for target, old in reversed(saved):
                if target.is_dir():
                    shutil.rmtree(target)
                    shutil.copytree(old, target)
                else:
                    shutil.copy2(old, target)
            raise
