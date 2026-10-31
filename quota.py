"""Transactional quota accounting core. Timestamps are UTC Unix seconds."""
from __future__ import annotations
import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

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

class Quotas:
    def __init__(self, path: str):
        self.path = path
        with self._db() as db:
            db.executescript(SCHEMA)

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
        expiry = None if row['first_connected'] is None else row['first_connected'] + row['days'] * 86400
        if not row['enabled']:
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
                      None if expiry is None else max(0, expiry-now))

    @staticmethod
    def _row(db, name):
        row = db.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
        if row is None:
            raise KeyError(name)
        return row

    def create_user(self, name: str, limit_bytes: int, days: int) -> str:
        if not name or len(name) > 64 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in name):
            raise ValueError('name must be 1-64 ASCII letters, digits, underscores or hyphens')
        if type(limit_bytes) is not int or type(days) is not int or limit_bytes <= 0 or days <= 0:
            raise ValueError('limits must be positive integers')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        with self._db() as db:
            db.execute('INSERT INTO users(name,token_hash,limit_bytes,days) VALUES(?,?,?,?)',
                       (name, digest, limit_bytes, days))
        return token

    def status(self, name: str, now=None) -> Status:
        with self._db() as db:
            return self._status(self._row(db, name), self._time(now))

    def status_by_token(self, token: str, now=None) -> Status | None:
        try:
            digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        except (UnicodeEncodeError, AttributeError):
            return None
        with self._db() as db:
            row = db.execute('SELECT * FROM users WHERE token_hash=?', (digest,)).fetchone()
            return None if row is None else self._status(row, self._time(now))

    def set_enabled(self, name: str, enabled: bool):
        if type(enabled) is not bool:
            raise ValueError('enabled must be bool')
        with self._db() as db:
            result = db.execute('UPDATE users SET enabled=? WHERE name=?', (int(enabled), name))
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
