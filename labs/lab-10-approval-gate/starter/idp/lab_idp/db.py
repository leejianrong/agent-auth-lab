"""The Lab IdP's own storage. It is a separate service with its own SQLite
file: the client app never reads this database, it only talks to the IdP
over HTTP, exactly like it would with a real identity provider."""

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("LAB_IDP_DB", Path(__file__).resolve().parent.parent / "lab10-idp.db"))

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
"""


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Lab 10: the audit log opens this same file on a second connection, and a
    # signed-in page now polls every second or two. In SQLite's default mode a
    # writer blocks readers and the loser gets "database is locked". WAL lets
    # readers and a writer carry on side by side.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
