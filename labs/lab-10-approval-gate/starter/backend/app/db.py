import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "lab10.db"

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
    expires_at REAL NOT NULL,
    -- Lab 05: sessions that came from the Lab IdP remember the access token
    -- they were issued, and check it with the IdP on every request.
    access_token TEXT,
    access_token_jti TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    owner_username TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Lab 07: agents are a row type of their own, not users with a flag. The
-- IdP holds their credentials; this table is the app's record of who they
-- are, who answers for them, and when they last did anything.
CREATE TABLE IF NOT EXISTS agents (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sponsor_sub TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Lab 09: a person asks an agent to do something for them. The row carries the
-- person's access token to the agent (which exchanges it for a narrower one)
-- and is wiped when the task finishes. LAB ONLY (ADR-0008): a real system would
-- not park a user's token in a table, it would pass it over an authenticated
-- channel and never store it.
CREATE TABLE IF NOT EXISTS agent_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    subject_token TEXT,
    trace_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    claimed_by TEXT
);

-- Lab 10: an elevated tool call waits here for a person to decide. The row says
-- exactly what is being asked for (`tool` and `args_json`, fingerprinted in
-- `args_digest`), who asked (`agent_id`, answerable to `sponsor`) and the trace
-- the request belongs to. Approving mints `approval_token`, which the agent
-- collects and presents once. LAB ONLY (ADR-0008): the token sits in the row so
-- the agent can fetch it; a real system would store a hash and hand the token
-- over once. It is wiped the moment it is used or expires.
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    agent_name TEXT,
    sponsor TEXT,
    tool TEXT NOT NULL,
    args_json TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    decided_by TEXT,
    decided_at REAL,
    decision_note TEXT,
    approval_token TEXT,
    token_expires_at REAL,
    used_at REAL
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
    # Lab 10: the audit log opens this same file on a second connection, and a
    # signed-in page now polls every second or two. In SQLite's default mode a
    # writer blocks readers and the loser gets "database is locked". WAL lets
    # readers and a writer carry on side by side.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def reset_db(db_path: Path = DB_PATH) -> None:
    """Used by tests to start from a clean database."""
    for path in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        if path.exists():
            path.unlink()
