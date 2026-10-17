"""The Lab IdP's own storage. It is a separate service with its own SQLite
file: the client app never reads this database, it only talks to the IdP
over HTTP, exactly like it would with a real identity provider."""

import os
import sqlite3
import threading
from pathlib import Path

DB_PATH = Path(os.environ.get("LAB_IDP_DB", Path(__file__).resolve().parent.parent / "lab12-idp.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS idp_users (
    sub TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce TEXT,
    sub TEXT NOT NULL,
    trace_id TEXT,
    scope TEXT NOT NULL DEFAULT 'openid',
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

-- Lab 05: what each user has agreed to share with each app, so the consent
-- screen only appears when an app asks for something new.
CREATE TABLE IF NOT EXISTS consents (
    sub TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at REAL NOT NULL,
    PRIMARY KEY (sub, client_id)
);

-- Lab 05: access tokens are self-contained JWTs, so "revoked" has to live
-- somewhere the IdP can look it up. The jti claim identifies one token.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at REAL NOT NULL
);

-- Lab 12: the kill-switch. Revoking one token stops one token; cutting off a
-- client stops every token it holds, and every token made from one of its.
CREATE TABLE IF NOT EXISTS revoked_clients (
    client_id TEXT PRIMARY KEY,
    revoked_at REAL NOT NULL,
    revoked_by TEXT NOT NULL,
    reason TEXT
);
"""


class _Result:
    """What `LockedConnection.execute` hands back: the rows are read while the
    lock is still held, so no other thread can touch the connection mid-fetch."""

    def __init__(self, rows: list, rowcount: int, lastrowid: int | None):
        self._rows, self.rowcount, self.lastrowid = rows, rowcount, lastrowid

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list:
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class LockedConnection:
    """One SQLite connection that is safe to share between FastAPI's worker
    threads. A single `sqlite3` connection must not be used by two threads at
    once ("bad parameter or other API misuse", or "database is locked"), and a
    page that polls several endpoints a second makes that happen. Every call
    takes the same lock, as the audit log has done since lab 07."""

    def __init__(self, raw: sqlite3.Connection):
        self._raw = raw
        self._lock = threading.RLock()

    def execute(self, sql: str, params=()) -> _Result:
        with self._lock:
            cur = self._raw.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
            return _Result(rows, cur.rowcount, cur.lastrowid)

    def executescript(self, script: str) -> None:
        with self._lock:
            self._raw.executescript(script)

    def commit(self) -> None:
        with self._lock:
            self._raw.commit()

    def close(self) -> None:
        with self._lock:
            self._raw.close()


def get_connection(db_path: Path = DB_PATH) -> "LockedConnection":
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Lab 10: the audit log opens this same file on a second connection, and a
    # signed-in page now polls every second or two. In SQLite's default mode a
    # writer blocks readers and the loser gets "database is locked". WAL lets
    # readers and a writer carry on side by side.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return LockedConnection(conn)
