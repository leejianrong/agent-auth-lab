"""The Lab IdP's own storage. It is a separate service with its own SQLite
file: the client app never reads this database, it only talks to the IdP
over HTTP, exactly like it would with a real identity provider."""

import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("LAB_IDP_DB", Path(__file__).resolve().parent.parent / "lab04-idp.db"))

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
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
