"""Bounded, authenticated migration backups; never extract untrusted tar paths."""
from contextlib import contextmanager
import gzip
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
from cryptography.fernet import Fernet, InvalidToken
from quota import link_key_path, read_link_key, TokenStorageError

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


class BoundedBuffer(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > MAX_ARCHIVE - 128:
            raise ValueError('Compressed backup too large')
        return super().write(data)


def verify_link_tokens(db, vault):
    columns={row[1] for row in db.execute('PRAGMA table_info(users)')}
    if 'encrypted_token' not in columns: return
    for digest,cipher in db.execute('SELECT token_hash,encrypted_token FROM users WHERE encrypted_token IS NOT NULL'):
        if vault is None: raise ValueError('Backup is missing the subscription key')
        try:
            if not isinstance(cipher,str) or len(cipher)>1024: raise ValueError('Invalid cipher')
            token=vault.decrypt(cipher.encode('ascii'))
            if hashlib.sha256(token).hexdigest()!=digest: raise ValueError('Invalid token')
        except (InvalidToken,ValueError,UnicodeError) as error:
            raise ValueError('Invalid encrypted link') from error


def capture(root=ROOT, database=DATABASE):
    """Caller holds the PKI lock. SQLite backup is transactionally consistent."""
    if database.stat().st_size > MAX_EXPANDED:
        raise ValueError('Database exceeds migration size limit')
    buffer = BoundedBuffer()
    with tempfile.TemporaryDirectory(prefix='panel-snapshot-') as temp:
        snapshot = Path(temp) / 'quota.sqlite'
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as source:
            with sqlite3.connect(snapshot) as dest:
                source.backup(dest)
                if dest.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Database integrity failed')
        total = snapshot.stat().st_size
        if total > MAX_EXPANDED:
            raise ValueError('Database snapshot too large')
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            manifest = json.dumps({'format': 2, 'created_at': int(time.time())}).encode()
            info = tarfile.TarInfo('manifest.json')
            info.size, info.mode = len(manifest), 0o600
            archive.addfile(info, io.BytesIO(manifest))
            archive.add(snapshot, arcname='var/lib/openvpn-panel/quota.sqlite', recursive=False)
            vault = link_key_path(database)
            data = read_link_key(vault) if vault.exists() or vault.is_symlink() else None
            with sqlite3.connect(snapshot) as check:
                verify_link_tokens(check,Fernet(data) if data is not None else None)
            if data is not None:
                info = tarfile.TarInfo('var/lib/openvpn-panel/quota.sqlite.links.key')
                info.size, info.mode = len(data),0o600
                archive.addfile(info,io.BytesIO(data))
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


@contextmanager
def bounded_archive(data):
    # Bound decompression BEFORE tarfile parses PAX/GNU metadata as well as file
    # contents. A small gzip upload must not allocate unlimited header memory.
    with tempfile.TemporaryFile() as expanded:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
            size = 0
            while chunk := source.read(65536):
                size += len(chunk)
                if size > MAX_EXPANDED + 16*1024**2:
                    raise ValueError('Expanded archive too large')
                expanded.write(chunk)
        expanded.seek(0)
        with tarfile.open(fileobj=expanded,mode='r:') as archive:
            yield archive


def validate_archive(data, stage):
    if len(data) > MAX_ARCHIVE:
        raise ValueError('Archive too large')
    total, seen = 0, set()
    with bounded_archive(data) as archive:
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
                'etc/openvpn-panel/crl.pem', 'etc/openvpn-panel/tls-crypt.key',
                'var/lib/openvpn-panel/quota.sqlite.links.key') or
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
    vault_path=stage/'var/lib/openvpn-panel/quota.sqlite.links.key'
    vault=None
    if vault_path.exists():
        try: vault=Fernet(read_link_key(vault_path))
        except TokenStorageError as error: raise ValueError('Invalid subscription key') from error
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
        columns={row[1] for row in db.execute('PRAGMA table_info(users)')}
        for field in ('valid_from','prior_usage','last_auth_at'):
            if field in columns and db.execute(f'SELECT 1 FROM users WHERE {field} IS NOT NULL AND (typeof({field})!="integer" OR {field}<0)').fetchone():
                raise ValueError('Invalid renewal metadata')
        if 'cert_serial' in columns:
            for serial, in db.execute('SELECT cert_serial FROM users WHERE cert_serial IS NOT NULL'):
                if serial!='pending' and (not isinstance(serial,str) or not re.fullmatch('[0-9A-F]{1,128}',serial)):
                    raise ValueError('Invalid certificate identity')
        if 'max_connections' in columns:
            if db.execute('SELECT 1 FROM users WHERE typeof(max_connections)!="integer" OR max_connections NOT BETWEEN 1 AND 100').fetchone():
                raise ValueError('Invalid connection limit')
        if 'deleted' in columns:
            if db.execute('SELECT 1 FROM users WHERE deleted NOT IN (0,1) OR deleted IS NULL OR (deleted=1 AND enabled!=0)').fetchone():
                raise ValueError('Invalid deleted-user state')
        verify_link_tokens(db,vault)
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
        source_key=stage/'var/lib/openvpn-panel/quota.sqlite.links.key'
        target_key=link_key_path(database)
        if source_key.exists(): items.append((target_key,source_key))
        saved = []
        try:
            for i, (target, source) in enumerate(items):
                old = rollback / str(i)
                if target.is_symlink(): raise ValueError('Restore target may not be a symlink')
                if target.is_dir(): shutil.copytree(target, old)
                elif target.exists(): shutil.copy2(target, old)
                else: old=None
                saved.append((target, old))
                if target.is_dir():
                    shutil.rmtree(target)
                    shutil.copytree(source, target)
                else:
                    shutil.copyfile(source, target)
                    target.chmod(0o660 if target == database else 0o600)
                    if target==target_key:
                        owner=database.stat()
                        os.chown(target,owner.st_uid,owner.st_gid)
            activate()
        except BaseException:
            deactivate()
            for target, old in reversed(saved):
                if old is None: target.unlink(missing_ok=True)
                elif target.is_dir():
                    shutil.rmtree(target)
                    shutil.copytree(old, target)
                else:
                    shutil.copy2(old, target)
            raise
