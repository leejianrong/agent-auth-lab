import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "lab04.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    idp_sub TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    owner_username TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Lab 04: one row per "Sign in with Lab IdP" attempt. The row holds the
-- secrets the client must remember between redirecting out and coming back
-- (the PKCE verifier and the nonce), keyed by the `state` value the IdP
-- echoes back on the callback.
CREATE TABLE IF NOT EXISTS oidc_flows (
    state TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    user_id INTEGER REFERENCES users(id),
    id_token_claims_json TEXT,
    outcome TEXT,
    failure_reason TEXT
);
"""


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def reset_db(db_path: Path = DB_PATH) -> None:
    """Used by tests to start from a clean database."""
    if db_path.exists():
        db_path.unlink()
