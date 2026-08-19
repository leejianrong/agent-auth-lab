import sqlite3
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from observability_harness import AuditLog, trace_context
from observability_harness.dashboard import create_dashboard_router

from . import security
from .db import get_connection

app = FastAPI(title="Lab 00: Sessions & Cookies")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

conn: sqlite3.Connection = get_connection()
audit_log = AuditLog(str(Path(__file__).resolve().parent.parent / "lab00.db"))

app.include_router(create_dashboard_router(audit_log), prefix="/observability")

SESSION_COOKIE = "session_id"


class Credentials(BaseModel):
    username: str
    password: str


@app.middleware("http")
async def bind_trace(request: Request, call_next):
    with trace_context():
        return await call_next(request)


def get_current_session(request: Request) -> sqlite3.Row:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise HTTPException(status_code=401, detail="no session cookie presented")

    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None:
        audit_log.record(
            actor_type="human", actor_id="unknown", action="authenticate",
            decision="deny", reason="session id not found",
        )
        raise HTTPException(status_code=401, detail="invalid session")

    if row["expires_at"] < time.time():
        audit_log.record(
            actor_type="human", actor_id=str(row["user_id"]), action="authenticate",
            decision="deny", reason="session expired",
        )
        raise HTTPException(status_code=401, detail="session expired")

    return row


@app.post("/signup", status_code=201)
def signup(creds: Credentials):
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="username already taken")

    password_hash = security.hash_password(creds.password)
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (creds.username, password_hash),
    )
    conn.commit()
    return {"username": creds.username}


@app.post("/login")
def login(creds: Credentials, response: Response, request: Request):
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (creds.username,)
    ).fetchone()

    if user is None or not security.verify_password(creds.password, user["password_hash"]):
        audit_log.record(
            actor_type="human", actor_id=creds.username, action="login",
            decision="deny", reason="bad credentials",
        )
        raise HTTPException(status_code=401, detail="invalid username or password")

    session_id = security.resolve_login_session_id(request.cookies.get(SESSION_COOKIE))

    now = time.time()
    conn.execute(
        "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (session_id, user["id"], now, security.session_expiry(now)),
    )
    conn.commit()

    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,  # local dev over http; set True behind real TLS
        max_age=security.SESSION_TTL_SECONDS,
    )
    audit_log.record(
        actor_type="human", actor_id=str(user["id"]), action="login", decision="allow",
    )
    return {"username": user["username"]}


@app.get("/me")
def me(session: sqlite3.Row = Depends(get_current_session)):
    user = conn.execute(
        "SELECT id, username FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return {"id": user["id"], "username": user["username"]}


@app.get("/sessions/mine")
def sessions_mine(session: sqlite3.Row = Depends(get_current_session)):
    """Powers the cookie/session inspector panel: what the server actually
    holds for this session, distinct from what the browser's cookie shows."""
    return {
        "session_id_prefix": session["id"][:8] + "…",
        "user_id": session["user_id"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
        "seconds_remaining": max(0, session["expires_at"] - time.time()),
    }


@app.post("/logout")
def logout(response: Response, session: sqlite3.Row = Depends(get_current_session)):
    conn.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
    conn.commit()
    response.delete_cookie(SESSION_COOKIE)
    audit_log.record(
        actor_type="human", actor_id=str(session["user_id"]), action="logout", decision="allow",
    )
    return {"ok": True}
