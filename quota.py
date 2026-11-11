"""Transactional quota accounting core. Timestamps are UTC Unix seconds."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from cryptography.fernet import Fernet, InvalidToken
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
 token_hash TEXT NOT NULL UNIQUE, limit_bytes INTEGER NOT NULL CHECK(limit_bytes > 0),
 days INTEGER NOT NULL CHECK(days > 0), first_connected INTEGER,
 used_bytes INTEGER NOT NULL DEFAULT 0 CHECK(used_bytes >= 0),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
 closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1))
);
'''

@dataclass(frozen=True)
class Status:
    name: str
    enabled: bool
    allowed: bool
    reason: str | None
    limit_bytes: int
    used_bytes: int
    remaining_bytes: int
    days: int
    first_connected: int | None
    expires_at: int | None
    remaining_seconds: int | None
    max_connections: int = 1
    valid_from: int | None = None
    last_auth_code: str | None = None
    last_auth_at: int | None = None

class TokenStorageError(RuntimeError):
    pass


def link_key_path(database):
    return Path(str(database)+'.links.key')


def read_link_key(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != 44 or info.st_mode & 0o077:
                raise ValueError('Invalid link key permissions or size')
            key = file.read(45)
            Fernet(key)
            return key
    except (OSError, ValueError) as error:
        raise TokenStorageError('Subscription key unavailable') from error


class Quotas:
    def __init__(self, path: str):
        self.path = path
        with self._db() as db:
            db.executescript(SCHEMA)
            db.execute('BEGIN IMMEDIATE')
            columns = {row[1] for row in db.execute('PRAGMA table_info(users)')}
            if 'encrypted_token' not in columns:
                db.execute('ALTER TABLE users ADD COLUMN encrypted_token TEXT')
            if 'max_connections' not in columns:
                db.execute('ALTER TABLE users ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 1 CHECK(max_connections BETWEEN 1 AND 100)')
            for field, declaration in {'valid_from':'INTEGER','prior_usage':'INTEGER NOT NULL DEFAULT 0 CHECK(prior_usage>=0)',
                    'cert_serial':'TEXT','original_name':'TEXT','last_auth_code':'TEXT','last_auth_at':'INTEGER'}.items():
                if field not in columns: db.execute(f'ALTER TABLE users ADD COLUMN {field} {declaration}')
            session_columns={row[1] for row in db.execute('PRAGMA table_info(sessions)')}
            if 'started_at' not in session_columns:
                db.execute('ALTER TABLE sessions ADD COLUMN started_at INTEGER NOT NULL DEFAULT 0')
            db.execute('CREATE INDEX IF NOT EXISTS sessions_active_user ON sessions(user_id) WHERE closed=0')
            if 'deleted' not in columns:
                db.execute('ALTER TABLE users ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1))')
            db.execute('CREATE INDEX IF NOT EXISTS users_visible_id ON users(id DESC) WHERE deleted=0')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            yield db
            if db.in_transaction:
                db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _time(now):
        return int(time.time()) if now is None else int(now)

    @staticmethod
    def _status(row, now):
        start = row['valid_from'] if row['valid_from'] is not None else row['first_connected']
        expiry = None if start is None else start + row['days'] * 86400
        if row['deleted'] or not row['enabled']:
            reason = 'disabled'
        elif row['used_bytes'] >= row['limit_bytes']:
            reason = 'volume_exhausted'
        elif expiry is not None and now >= expiry:
            reason = 'expired'
        else:
            reason = None
        return Status(row['name'], bool(row['enabled']), reason is None, reason,
                      row['limit_bytes'], row['used_bytes'], max(0, row['limit_bytes']-row['used_bytes']),
                      row['days'], row['first_connected'], expiry,
                      None if expiry is None else max(0, expiry-now), row['max_connections'], start, row['last_auth_code'], row['last_auth_at'])

    @staticmethod
    def _row(db, name):
        row = db.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
        if row is None:
            raise KeyError(name)
        return row

    def create_user(self, name: str, limit_bytes: int, days: int, *, remember=False, max_connections=1) -> str:
        if type(max_connections) is not int or not 1 <= max_connections <= 100:
            raise ValueError('invalid connection limit')
        if not name or len(name) > 64 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in name):
            raise ValueError('name must be 1-64 ASCII letters, digits, underscores or hyphens')
        if type(limit_bytes) is not int or type(days) is not int or limit_bytes <= 0 or days <= 0:
            raise ValueError('limits must be positive integers')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        encrypted = self._encrypt_token(token) if remember else None
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT id,deleted FROM users WHERE name=?',(name,)).fetchone()
            serial=None
            if previous and previous['deleted']:
                # Retain history but free the public name. Never authorize the old
                # certificate while a new generation is awaiting root issuance.
                serial='pending'
                archived='deleted_'+str(previous['id'])+'_'+secrets.token_hex(8)
                db.execute('UPDATE users SET name=?,original_name=? WHERE id=?',(archived,name,previous['id']))
                db.execute('UPDATE sessions SET closed=1 WHERE user_id=?',(previous['id'],))
            db.execute('INSERT INTO users(name,token_hash,limit_bytes,days,encrypted_token,max_connections,cert_serial) VALUES(?,?,?,?,?,?,?)',
                       (name, digest, limit_bytes, days, encrypted, max_connections, serial))
        return token

    def status(self, name: str, now=None) -> Status:
        with self._db() as db:
            row = self._row(db, name)
            if row['deleted']: raise KeyError(name)
            return self._status(row, self._time(now))

    def status_by_token(self, token: str, now=None) -> Status | None:
        try:
            digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        except (UnicodeEncodeError, AttributeError):
            return None
        with self._db() as db:
            row = db.execute('SELECT * FROM users WHERE token_hash=? AND deleted=0', (digest,)).fetchone()
            return None if row is None else self._status(row, self._time(now))

    def set_enabled(self, name: str, enabled: bool):
        if type(enabled) is not bool:
            raise ValueError('enabled must be bool')
        with self._db() as db:
            result = db.execute('UPDATE users SET enabled=? WHERE name=? AND deleted=0', (int(enabled), name))
            if not result.rowcount:
                raise KeyError(name)

    def connect(self, name: str, session_id: str, now=None) -> Status:
        """Record a successful connection once. Reject disallowed users atomically."""
        if not session_id or len(session_id) > 256:
            raise ValueError('invalid session id')
        now = self._time(now)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self._row(db, name)
            state = self._status(row, now)
            if not state.allowed:
                raise PermissionError(state.reason)
            db.execute('INSERT INTO sessions(id,user_id) VALUES(?,?)', (session_id, row['id']))
            db.execute('UPDATE users SET first_connected=COALESCE(first_connected, ?) WHERE id=?', (now, row['id']))
            return self._status(self._row(db, name), now)

    def account(self, session_id: str, rx: int, tx: int, *, final=False, now=None) -> Status:
        """Apply cumulative byte counters exactly once; reject resets/out-of-order values."""
        if any(type(x) is not int or x < 0 for x in (rx, tx)):
            raise ValueError('counters must be nonnegative integers')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            session = db.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
            if session is None:
                raise KeyError(session_id)
            if session['closed']:
                if (rx, tx) != (session['rx'], session['tx']):
                    raise ValueError('session already closed')
            else:
                if rx < session['rx'] or tx < session['tx']:
                    raise ValueError('counters must be monotonic')
                delta = rx-session['rx'] + tx-session['tx']
                db.execute('UPDATE users SET used_bytes=used_bytes+? WHERE id=?', (delta, session['user_id']))
                db.execute('UPDATE sessions SET rx=?,tx=?,closed=? WHERE id=?', (rx,tx,int(final),session_id))
            row = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
            return self._status(row, self._time(now))

    def list_users(self, now=None) -> list[Status]:
        with self._db() as db:
            return [self._status(row, self._time(now)) for row in
                    db.execute('SELECT * FROM users WHERE deleted=0 ORDER BY id DESC')]

    def dashboard_page(self, search='', status='all', page=1, per_page=20, online=None, now=None):
        """One consistent read snapshot; materialize only the visible page.

        Names are ASCII, so SQLite lower/instr matches the old literal casefold
        search without treating underscores or percent signs as SQL wildcards.
        A temporary table avoids SQLite's parameter limit for large online sets.
        """
        if per_page not in (20,50,100) or type(page) is not int or page < 1:
            raise ValueError('invalid pagination')
        now=self._time(now)
        expiry='(COALESCE(valid_from,first_connected)+days*86400)'
        active=f'(enabled=1 AND used_bytes<limit_bytes AND ({expiry} IS NULL OR {expiry}>:now))'
        filters={
            'all':'1', 'active':active, 'disabled':'enabled=0',
            'expired':f'{expiry}<=:now', 'limited':'used_bytes>=limit_bytes',
            'online':'EXISTS(SELECT 1 FROM dashboard_online o WHERE o.name=users.name)',
            'near_limit':f'{active} AND (limit_bytes-used_bytes)<=limit_bytes*0.1',
            'near_expiry':f'{active} AND {expiry}-:now<=259200',
        }
        if status not in filters: raise ValueError('invalid status filter')
        params={'now':now,'search':search[:64].casefold(), 'limit':per_page}
        where='deleted=0 AND instr(lower(name),:search)>0 AND ('+filters[status]+')'
        with self._db() as db:
            db.execute('CREATE TEMP TABLE dashboard_online(name TEXT PRIMARY KEY) WITHOUT ROWID')
            db.executemany('INSERT OR IGNORE INTO dashboard_online VALUES(?)',((name,) for name in (online or ())))
            db.execute('BEGIN')
            total=db.execute('SELECT COUNT(*) FROM users WHERE '+where,params).fetchone()[0]
            pages=max(1,(total+per_page-1)//per_page)
            page=min(page,pages)
            params['offset']=(page-1)*per_page
            rows=db.execute('SELECT * FROM users WHERE '+where+' ORDER BY id DESC LIMIT :limit OFFSET :offset',params).fetchall()
            counts=db.execute(f'SELECT COUNT(*) total, COALESCE(SUM(enabled=0),0) disabled, '
                f'COALESCE(SUM({expiry}<=:now),0) expired, COALESCE(SUM(used_bytes>=limit_bytes),0) exhausted, '
                'COALESCE(SUM(EXISTS(SELECT 1 FROM dashboard_online o WHERE o.name=users.name)),0) online '
                'FROM users WHERE deleted=0',params).fetchone()
            stats=dict(counts)
            if online is None: stats['online']=None
            stats['traffic']=db.execute('SELECT COALESCE(SUM(used_bytes+prior_usage),0) FROM users').fetchone()[0]
            return dict(users=[self._status(row,now) for row in rows],stats=stats,total=total,page=page,pages=pages)

    def rotate_token(self, name: str, *, remember=False) -> str:
        token = secrets.token_urlsafe(32)
        encrypted = self._encrypt_token(token) if remember else None
        with self._db() as db:
            result = db.execute('UPDATE users SET token_hash=?,encrypted_token=? WHERE name=? AND deleted=0',
                                (hashlib.sha256(token.encode('ascii')).hexdigest(), encrypted, name))
            if not result.rowcount:
                raise KeyError(name)
        return token

    def _encrypt_token(self, token):
        path = link_key_path(self.path)
        if not path.exists() and not path.is_symlink():
            with self._db() as db:
                if db.execute('SELECT 1 FROM users WHERE encrypted_token IS NOT NULL LIMIT 1').fetchone():
                    raise TokenStorageError('Restore the missing subscription key before writing new links')
            try: fd, temp = tempfile.mkstemp(prefix='.link-key-', dir=path.parent)
            except OSError as error: raise TokenStorageError('Cannot create subscription key') from error
            try:
                with os.fdopen(fd,'wb') as out:
                    out.write(Fernet.generate_key())
                    out.flush()
                    os.fsync(out.fileno())
                try: os.link(temp,path)  # Publish complete bytes, never overwrite an existing key.
                except FileExistsError: pass
            except OSError as error:
                raise TokenStorageError('Cannot create subscription key') from error
            finally:
                Path(temp).unlink(missing_ok=True)
        return Fernet(read_link_key(path)).encrypt(token.encode('ascii')).decode('ascii')

    def remembered_token(self, name):
        with self._db() as db:
            row = self._row(db,name)
            if row['deleted']: raise KeyError(name)
            if row['encrypted_token'] is None: return None
            try:
                token = Fernet(read_link_key(link_key_path(self.path))).decrypt(row['encrypted_token'].encode('ascii')).decode('ascii')
                if hashlib.sha256(token.encode('ascii')).hexdigest() != row['token_hash']:
                    raise ValueError('Token mismatch')
                return token
            except (InvalidToken, ValueError, UnicodeError) as error:
                raise TokenStorageError('Subscription link cannot be decrypted') from error

    def delete_user(self, name):
        # Retain a tombstone; safe reuse archives it and requires a fresh certificate.
        with self._db() as db:
            if not db.execute('UPDATE users SET deleted=1,enabled=0,encrypted_token=NULL,token_hash=? WHERE name=? AND deleted=0',
                              (hashlib.sha256(secrets.token_bytes(32)).hexdigest(),name)).rowcount:
                raise KeyError(name)

    def total_traffic(self):
        with self._db() as db:
            return db.execute('SELECT COALESCE(SUM(used_bytes+prior_usage),0) FROM users').fetchone()[0]

    def update_limits(self, name: str, limit_bytes: int, days: int, max_connections=None, *, reset_usage=False, renew_now=False, enable=False, now=None):
        """Change total allowance, preserving usage and first activation."""
        if type(limit_bytes) is not int or not 1 <= limit_bytes <= 100000 * 1024**3:
            raise ValueError('invalid volume')
        if type(days) is not int or not 1 <= days <= 3650:
            raise ValueError('invalid days')
        if max_connections is not None and (type(max_connections) is not int or not 1 <= max_connections <= 100):
            raise ValueError('invalid connection limit')
        if any(type(value) is not bool for value in (reset_usage,renew_now,enable)): raise ValueError('invalid reset options')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('UPDATE users SET limit_bytes=?, days=?, max_connections=COALESCE(?,max_connections), '
                              'prior_usage=prior_usage+CASE WHEN ? THEN used_bytes ELSE 0 END, '
                              'used_bytes=CASE WHEN ? THEN 0 ELSE used_bytes END, '
                              'valid_from=CASE WHEN ? THEN ? ELSE valid_from END, '
                              'enabled=CASE WHEN ? THEN 1 ELSE enabled END WHERE name=? AND deleted=0',
                              (limit_bytes, days, max_connections,reset_usage,reset_usage,renew_now,self._time(now),enable,name)).rowcount:
                raise KeyError(name)

    def reset_sessions(self):
        """Only run before starting a new OpenVPN process (old counters are gone)."""
        with self._db() as db:
            db.execute('UPDATE sessions SET closed=1 WHERE closed=0')

    def vpn_connect(self, name: str, address: str, now=None, *, serial=None):
        """Atomically reserve one of the configured simultaneous connection slots."""
        now = self._time(now)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self._row(db, name)
            state = self._status(row, now)
            if not state.allowed:
                raise PermissionError(state.reason)
            if row['cert_serial'] is not None:
                if row['cert_serial']=='pending' or serial is None or normalize_serial(serial) != row['cert_serial']:
                    raise PermissionError('old_certificate')
            count = db.execute('SELECT count(*) FROM sessions WHERE user_id=? AND closed=0', (row['id'],)).fetchone()[0]
            sid = name + '|' + address
            if count >= row['max_connections'] or db.execute('SELECT 1 FROM sessions WHERE id=? AND closed=0',(sid,)).fetchone():
                raise PermissionError('connection_limit')
            # Reusing a UDP source address after a disconnect must not reuse counters.
            sid = name + '|' + address
            db.execute('DELETE FROM sessions WHERE id=? AND closed=1', (sid,))
            db.execute('INSERT INTO sessions(id,user_id,started_at) VALUES(?,?,?)', (sid, row['id'],now))
            # client-connect runs after certificate authentication, before tunnel admission.
            db.execute('UPDATE users SET first_connected=COALESCE(first_connected, ?) WHERE id=?',
                       (now, row['id']))

    def vpn_account(self, name: str, address: str, rx: int, tx: int, *, final=False, now=None):
        """Snapshot/final-hook race safe: a stale snapshot never decreases counters."""
        if any(type(x) is not int or x < 0 or x > 2**62 for x in (rx, tx)):
            raise ValueError('invalid counters')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self._row(db, name)
            sid = name + '|' + address
            s = db.execute('SELECT * FROM sessions WHERE id=? AND user_id=?', (sid, row['id'])).fetchone()
            if s is None:
                raise KeyError('untracked connection')
            if not s['closed']:
                rx, tx = max(rx, s['rx']), max(tx, s['tx'])
                delta = rx - s['rx'] + tx - s['tx']
                db.execute('UPDATE users SET used_bytes=used_bytes+? WHERE id=?', (delta, row['id']))
                db.execute('UPDATE sessions SET rx=?,tx=?,closed=? WHERE id=?', (rx, tx, int(final), sid))
            state=self._status(self._row(db, name), self._time(now))
            return replace(state,allowed=False,reason='session_closed') if s['closed'] and not final else state

    def session_registered(self, name, address):
        with self._db() as db:
            return db.execute('SELECT 1 FROM sessions s JOIN users u ON s.user_id=u.id WHERE u.name=? AND s.id=? AND s.closed=0',
                              (name,name+'|'+address)).fetchone() is not None

    def reconcile_sessions(self, live, now=None):
        """Reap missed disconnect hooks only after a full snapshot and 30s grace."""
        now=self._time(now)
        live={name+'|'+address for name,address in live}
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute('SELECT id FROM sessions WHERE closed=0 AND started_at<=?',(now-30,)).fetchall():
                if row['id'] not in live: db.execute('UPDATE sessions SET closed=1 WHERE id=?',(row['id'],))

    def record_auth(self,name,code,now=None):
        allowed={'accepted','disabled','expired','volume_exhausted','connection_limit','old_certificate',
                 'credential_rotating','accounting_unavailable','internal_error'}
        if code not in allowed: raise ValueError('invalid diagnostic code')
        with self._db() as db:
            db.execute('UPDATE users SET last_auth_code=?,last_auth_at=? WHERE name=? AND deleted=0',(code,self._time(now),name))


def normalize_serial(value):
    import re
    if not isinstance(value,str) or not re.fullmatch(r'[0-9A-Fa-f:]{1,128}',value):
        raise PermissionError('old_certificate')
    return value.replace(':','').upper().lstrip('0') or '0'
