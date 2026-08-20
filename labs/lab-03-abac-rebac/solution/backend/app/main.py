import sqlite3
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from observability_harness import AuditLog, trace_context
from observability_harness.dashboard import create_dashboard_router

from . import policy, security
from .db import get_connection

app = FastAPI(title="Lab 03: ABAC/ReBAC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

conn: sqlite3.Connection = get_connection()
audit_log = AuditLog(str(Path(__file__).resolve().parent.parent / "lab03.db"))

app.include_router(create_dashboard_router(audit_log), prefix="/observability")

SESSION_COOKIE = "session_id"

# ADR-0008: a fixed, checked-in admin credential so the lab has a working
# admin account with zero setup — never do this outside a localhost
# teaching exercise. A real system provisions its first admin through a
# separate, audited bootstrap step (a one-time CLI command, a manual DB
# migration reviewed by someone), never a password baked into source
# control that every clone of the repo shares.
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "lab02-admin-do-not-reuse"


class Credentials(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class VerifyRequest(BaseModel):
    token: str


class VerifyResponse(BaseModel):
    valid: bool
    signature_valid: bool
    expired: bool
    claims: dict | None = None
    reason: str | None = None


class UserSummary(BaseModel):
    id: int
    username: str
    role: str


class NoteCreate(BaseModel):
    title: str
    body: str


class NoteUpdate(BaseModel):
    title: str
    body: str


class Note(BaseModel):
    id: int
    owner_id: int
    owner_username: str
    title: str
    body: str
    created_at: float


class NoteDecision(BaseModel):
    """What the policy-decision trace viewer renders: not just allow/deny,
    but the specific rule that produced it. `note` is populated only when
    `allowed` is true — a denial never leaks the resource's content, only
    the fact that it was denied and why."""

    allowed: bool
    rule_id: str
    rule_description: str
    note: Note | None = None


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


def get_current_user(session: sqlite3.Row = Depends(get_current_session)) -> sqlite3.Row:
    """The authenticated caller's own row — including their `role`, read
    from the database, never from anything the client sent on this
    request. Every role-gated route depends on this (via `require_role`
    below), never on a role field the caller could just supply itself."""
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="user for session not found")
    return user


def require_role(*allowed_roles: str, action: str, resource: str | None = None):
    """Build a FastAPI dependency that only admits callers whose role is
    accepted by `allowed_roles` — in the spirit of `get_current_session`
    above: a plain dependency, not a decorator, so it composes with
    `Depends()` like any other and can gate any route that declares it.

    The actual role check is `security.role_is_authorized`, kept as a
    standalone function so it's unit-testable on its own. `action` and
    `resource` describe what's being attempted, purely for the audit log —
    a caller denied here always gets a `deny` event naming the role their
    route required and the role they actually had.
    """
    def check_role(user: sqlite3.Row = Depends(get_current_user)) -> sqlite3.Row:
        if not security.role_is_authorized(user["role"], allowed_roles):
            audit_log.record(
                actor_type="human", actor_id=str(user["id"]), action=action,
                resource=resource, decision="deny",
                reason=(
                    f"requires role in {list(allowed_roles)}, "
                    f"caller has role '{user['role']}'"
                ),
            )
            raise HTTPException(status_code=403, detail="insufficient role")
        return user
    return check_role


def _seed_default_admin() -> None:
    """Give the lab a working admin account out of the box — see the
    ADR-0008 callout on `DEFAULT_ADMIN_PASSWORD` above."""
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)
    ).fetchone()
    if existing:
        return
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        (DEFAULT_ADMIN_USERNAME, security.hash_password(DEFAULT_ADMIN_PASSWORD)),
    )
    conn.commit()


_seed_default_admin()


@app.post("/signup", status_code=201)
def signup(creds: Credentials):
    """Self-service signup always gets the `user` role — hardcoded here,
    not read from anything the request supplied, because `Credentials`
    above has no `role` field for a client to set in the first place.
    Becoming `admin` never happens through this endpoint."""
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="username already taken")

    password_hash = security.hash_password(creds.password)
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
        (creds.username, password_hash),
    )
    conn.commit()
    return {"username": creds.username, "role": "user"}


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
def me(user: sqlite3.Row = Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@app.get("/admin/users", response_model=list[UserSummary])
def list_users(
    admin: sqlite3.Row = Depends(
        require_role("admin", action="list_users", resource="admin_panel")
    ),
):
    """Admin-only: every user in the system and their role. Powers the
    admin panel's user table — the one thing in this lab a non-admin
    should never be able to load."""
    rows = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    audit_log.record(
        actor_type="human", actor_id=str(admin["id"]), action="list_users",
        resource="admin_panel", decision="allow",
    )
    return [{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows]


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


@app.post("/token", response_model=TokenResponse)
def issue_token(session: sqlite3.Row = Depends(get_current_session)):
    """Issue a JWT for the caller's already-authenticated session — a
    second, stateless proof of identity alongside the session cookie, not a
    replacement for it. Requires the session cookie because the learner
    needs to already be logged in to obtain one."""
    user = conn.execute(
        "SELECT id, username FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    token = security.issue_token(user["username"])
    audit_log.record(
        actor_type="human", actor_id=str(user["id"]), action="issue_token", decision="allow",
    )
    return TokenResponse(access_token=token, expires_in=security.JWT_TTL_SECONDS)


@app.post("/verify", response_model=VerifyResponse)
def verify(payload: VerifyRequest):
    """Check a JWT's signature, expiry, and required claims. Deliberately
    takes no session cookie: this is the one thing the browser can't do for
    itself, since only the server holds `JWT_SECRET`. Powers the "verify
    with server" half of the JWT decoder panel."""
    result = security.verify_token(payload.token)
    actor_id = (result.claims or {}).get("sub", "unknown")
    if result.valid:
        audit_log.record(
            actor_type="human", actor_id=str(actor_id), action="verify_token", decision="allow",
        )
    else:
        audit_log.record(
            actor_type="human", actor_id=str(actor_id), action="verify_token",
            decision="deny", reason=result.reason,
        )
    return VerifyResponse(
        valid=result.valid,
        signature_valid=result.signature_valid,
        expired=result.expired,
        claims=result.claims,
        reason=result.reason,
    )


# --- lab 03: ABAC/ReBAC notes ----------------------------------------------
#
# RBAC (lab 02) can only express "does this role get in the door at all" for
# a whole route. Notes need a finer-grained answer: "can this caller read or
# write THIS note," which depends on whether they own it, not just their
# role. `policy.evaluate` (app/policy.py) makes that decision and names the
# specific rule that produced it — the "which rule fired" the trace viewer
# shows.


def _note_row_to_model(row: sqlite3.Row) -> Note:
    return Note(
        id=row["id"],
        owner_id=row["owner_id"],
        owner_username=row["owner_username"],
        title=row["title"],
        body=row["body"],
        created_at=row["created_at"],
    )


def _get_note_or_404(note_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="note not found")
    return row


def _evaluate_note_access(user: sqlite3.Row, note_row: sqlite3.Row, action: str) -> policy.PolicyDecision:
    """Run the policy evaluator for `action` on `note_row`, then audit-log
    the outcome with the matched rule's ID and description attached — every
    allow and every deny on a note names the specific rule that decided it,
    not just "the policy evaluator ran"."""
    subject = policy.Subject(id=user["id"], role=user["role"])
    resource = policy.ResourceAttrs(owner_id=note_row["owner_id"])
    decision = policy.evaluate(subject, resource, action)

    audit_log.record(
        actor_type="human", actor_id=str(user["id"]), action=f"{action}_note",
        resource=f"note:{note_row['id']}",
        decision="allow" if decision.allow else "deny",
        reason=f"matched rule '{decision.rule_id}': {decision.rule_description}",
        metadata={"rule_id": decision.rule_id, "rule_description": decision.rule_description},
    )
    return decision


@app.post("/notes", response_model=Note, status_code=201)
def create_note(payload: NoteCreate, user: sqlite3.Row = Depends(get_current_user)):
    """Every note is created owned by its caller — there's no field on
    `NoteCreate` for a client to hand in a different owner, same principle
    as `signup` never accepting a client-supplied role."""
    now = time.time()
    cursor = conn.execute(
        "INSERT INTO notes (owner_id, owner_username, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (user["id"], user["username"], payload.title, payload.body, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (cursor.lastrowid,)).fetchone()
    audit_log.record(
        actor_type="human", actor_id=str(user["id"]), action="create_note",
        resource=f"note:{row['id']}", decision="allow",
    )
    return _note_row_to_model(row)


@app.get("/notes/mine", response_model=list[Note])
def list_my_notes(user: sqlite3.Row = Depends(get_current_user)):
    """Your own notes only — a convenience list so you have IDs to try
    reading/writing as someone else in the panel below, not a general note
    directory."""
    rows = conn.execute(
        "SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],)
    ).fetchall()
    return [_note_row_to_model(r) for r in rows]


@app.get("/notes/{note_id}", response_model=NoteDecision)
def read_note(note_id: int, user: sqlite3.Row = Depends(get_current_user)):
    note_row = _get_note_or_404(note_id)
    decision = _evaluate_note_access(user, note_row, "read")
    if not decision.allow:
        raise HTTPException(
            status_code=403,
            detail={
                "allowed": False,
                "rule_id": decision.rule_id,
                "rule_description": decision.rule_description,
                "note": None,
            },
        )
    return NoteDecision(
        allowed=True, rule_id=decision.rule_id, rule_description=decision.rule_description,
        note=_note_row_to_model(note_row),
    )


@app.put("/notes/{note_id}", response_model=NoteDecision)
def update_note(note_id: int, payload: NoteUpdate, user: sqlite3.Row = Depends(get_current_user)):
    note_row = _get_note_or_404(note_id)
    decision = _evaluate_note_access(user, note_row, "write")
    if not decision.allow:
        raise HTTPException(
            status_code=403,
            detail={
                "allowed": False,
                "rule_id": decision.rule_id,
                "rule_description": decision.rule_description,
                "note": None,
            },
        )
    conn.execute(
        "UPDATE notes SET title = ?, body = ? WHERE id = ?",
        (payload.title, payload.body, note_id),
    )
    conn.commit()
    updated_row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return NoteDecision(
        allowed=True, rule_id=decision.rule_id, rule_description=decision.rule_description,
        note=_note_row_to_model(updated_row),
    )
