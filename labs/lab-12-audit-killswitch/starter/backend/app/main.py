import json
import re
import secrets
import sqlite3
import time
from urllib.parse import urlencode
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from observability_harness import AuditLog, current_trace_id, new_trace_id, trace_context
from observability_harness.dashboard import create_dashboard_router

from . import approvals, oidc_client, opa_client, policy, security, traces
from .db import get_connection

app = FastAPI(title="Lab 12: one trace, one kill-switch")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

conn = get_connection()
audit_log = AuditLog(str(Path(__file__).resolve().parent.parent / "lab12.db"))

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


_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")


@app.middleware("http")
async def bind_trace(request: Request, call_next):
    """Continue the caller's trace when it sends a well-formed X-Trace-Id (a
    service calling in, or the app calling the IdP and back), otherwise start
    a fresh one at the edge."""
    candidate = request.headers.get("x-trace-id", "")
    with trace_context(candidate if _TRACE_RE.match(candidate) else None):
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

    if row["access_token"]:
        # This session came from the Lab IdP, so it is only as alive as the
        # access token behind it. Ask the IdP every time: a revoked token
        # ends the session on the user's very next request.
        result = oidc_client.introspect(row["access_token"])
        if not result.get("active"):
            conn.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
            conn.commit()
            audit_log.record(
                actor_type="human", actor_id=str(row["user_id"]), action="authenticate",
                decision="deny", reason="session ended: the IdP says the access token is no longer active",
            )
            raise HTTPException(status_code=401, detail="session ended: access token revoked or expired")
        request.state.token_scope = result.get("scope", "")

    return row


def require_scope(scope: str, *, action: str, resource: str | None = None):
    """Gate a route on an OAuth scope. Sessions from a password login carry
    no access token and aren't limited by scopes; sessions from the Lab IdP
    are limited to what the user agreed to share at the consent screen."""
    def check(request: Request, user: sqlite3.Row = Depends(get_current_user)) -> sqlite3.Row:
        granted = getattr(request.state, "token_scope", None)
        if granted is None:
            return user
        if not oidc_client.has_scope(granted, scope):
            audit_log.record(
                actor_type="human", actor_id=str(user["id"]), action=action, resource=resource,
                decision="deny", reason=f"insufficient_scope: needs '{scope}', token grants '{granted}'",
            )
            raise HTTPException(status_code=403, detail="insufficient_scope")
        return user
    return check


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


# --- lab 04: "Sign in with Lab IdP" (OIDC authorization code + PKCE) -------

def _oidc_failure(trace_id: str, reason: str, state_row: sqlite3.Row | None = None) -> RedirectResponse:
    """Record a failed login and send the browser back to the UI, which
    shows the trace. The reason goes to the audit log and the trace viewer;
    the browser only gets a short code."""
    audit_log.record(
        actor_type="service", actor_id=oidc_client.CLIENT_ID, action="oidc_callback",
        resource="/auth/oidc/callback", decision="deny", reason=reason,
    )
    if state_row is not None:
        conn.execute(
            "UPDATE oidc_flows SET outcome = 'failed', failure_reason = ? WHERE state = ?",
            (reason, state_row["state"]),
        )
        conn.commit()
    query = urlencode({"oidc_error": "login_failed", "oidc_trace": trace_id})
    return RedirectResponse(f"{oidc_client.FRONTEND_URL}/?{query}", status_code=302)


@app.get("/auth/oidc/login")
def oidc_login():
    """Start a login: remember the secrets we'll need on the way back, then
    send the browser to the IdP carrying only the PKCE *challenge*."""
    trace_id = new_trace_id()
    with trace_context(trace_id):
        code_verifier, code_challenge = oidc_client.make_pkce_pair()
        state = oidc_client.new_state()
        nonce = oidc_client.new_nonce()
        conn.execute(
            "INSERT INTO oidc_flows (state, code_verifier, nonce, trace_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (state, code_verifier, nonce, trace_id, time.time()),
        )
        conn.commit()
        audit_log.record(
            actor_type="service", actor_id=oidc_client.CLIENT_ID, action="oidc_start",
            resource="/auth/oidc/login", decision="allow",
            reason="redirecting the browser to the IdP with a PKCE challenge, a state and a nonce",
            metadata={"code_challenge_len": len(code_challenge), "challenge_equals_verifier": code_challenge == code_verifier},
        )
        url = oidc_client.build_authorize_url(
            state=state, nonce=nonce, code_challenge=code_challenge, trace_id=trace_id,
        )
    return RedirectResponse(url, status_code=302)


def _upsert_idp_user(claims: dict) -> sqlite3.Row:
    """Map the IdP's stable `sub` to a local user row, creating one on first
    login. Federated users get the ordinary `user` role and a random password
    nobody knows, so the only way in is through the IdP."""
    user = conn.execute("SELECT * FROM users WHERE idp_sub = ?", (claims["sub"],)).fetchone()
    if user is not None:
        return user
    username = f"{claims.get('preferred_username', claims['sub'])}@lab-idp"
    conn.execute(
        "INSERT INTO users (username, password_hash, role, idp_sub) VALUES (?, ?, 'user', ?)",
        (username, security.hash_password(secrets.token_urlsafe(32)), claims["sub"]),
    )
    conn.commit()
    return conn.execute("SELECT * FROM users WHERE idp_sub = ?", (claims["sub"],)).fetchone()


@app.get("/auth/oidc/callback")
def oidc_callback(code: str | None = None, state: str | None = None, error: str | None = None):
    flow = conn.execute("SELECT * FROM oidc_flows WHERE state = ?", (state,)).fetchone() if state else None
    if flow is None:
        # No flow means we can't trust anything on this request, and we have
        # no trace to continue. This is the forged-callback / CSRF case.
        with trace_context():
            return _oidc_failure(new_trace_id(), "callback state is missing or unknown")

    with trace_context(flow["trace_id"]):
        trace_id = flow["trace_id"]
        if flow["used"]:
            return _oidc_failure(trace_id, "callback state was already used (replayed callback)", flow)
        conn.execute("UPDATE oidc_flows SET used = 1 WHERE state = ?", (state,))
        conn.commit()

        if error:
            return _oidc_failure(trace_id, f"the IdP returned an error: {error}", flow)
        if not code:
            return _oidc_failure(trace_id, "callback has no authorization code", flow)

        try:
            tokens = oidc_client.exchange_code(code, flow["code_verifier"])
        except oidc_client.OidcError as e:
            audit_log.record(
                actor_type="service", actor_id=oidc_client.CLIENT_ID, action="oidc_token_request",
                resource="/token", decision="deny", reason=e.reason,
            )
            return _oidc_failure(trace_id, e.reason, flow)
        audit_log.record(
            actor_type="service", actor_id=oidc_client.CLIENT_ID, action="oidc_token_request",
            resource="/token", decision="allow", reason="token endpoint returned an ID token and an access token",
        )

        try:
            claims = oidc_client.validate_id_token(tokens["id_token"], expected_nonce=flow["nonce"])
        except oidc_client.OidcError as e:
            audit_log.record(
                actor_type="service", actor_id=oidc_client.CLIENT_ID, action="id_token_validate",
                resource="id_token", decision="deny", reason=e.reason,
            )
            return _oidc_failure(trace_id, e.reason, flow)
        audit_log.record(
            actor_type="service", actor_id=oidc_client.CLIENT_ID, action="id_token_validate",
            resource="id_token", decision="allow",
            reason="signature, issuer, audience, expiry and nonce all check out",
        )

        grant = oidc_client.introspect(tokens["access_token"])
        if not grant.get("active"):
            return _oidc_failure(trace_id, "the IdP says the access token it just issued is not active", flow)
        audit_log.record(
            actor_type="service", actor_id=oidc_client.CLIENT_ID, action="token_introspect",
            resource="access_token", decision="allow", reason=f"access token is active, scopes: {grant.get('scope', '')}",
        )

        user = _upsert_idp_user(claims)
        session_id = security.new_session_id()
        now = time.time()
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, access_token, access_token_jti) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, user["id"], now, security.session_expiry(now), tokens["access_token"], grant["jti"]),
        )
        conn.execute(
            "UPDATE oidc_flows SET user_id = ?, id_token_claims_json = ?, outcome = 'success' WHERE state = ?",
            (user["id"], json.dumps(claims), state),
        )
        conn.commit()
        audit_log.record(
            actor_type="human", actor_id=str(user["id"]), action="login", decision="allow",
            reason="signed in through the Lab IdP", metadata={"idp_sub": claims["sub"]},
        )

        response = RedirectResponse(
            f"{oidc_client.FRONTEND_URL}/?{urlencode({'oidc_trace': trace_id})}", status_code=302
        )
        response.set_cookie(
            key=SESSION_COOKIE, value=session_id, httponly=True, samesite="lax",
            secure=False,  # local dev over http; set True behind real TLS
            max_age=security.SESSION_TTL_SECONDS,
        )
        return response


# --- lab 06: service-to-service ---------------------------------------------

def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    return header[7:].strip() or None if header.lower().startswith("bearer ") else None


def _audit_actor(
    actor: oidc_client.Actor, action: str, resource: str, allowed: bool, reason: str, extra: dict | None = None,
) -> None:
    """Record one decision about a service or agent, attributed to whoever
    the token says it is and, for an agent, to its sponsor. For an agent that
    was handed a person's authority by another agent, `via` names the agents
    it came through."""
    audit_log.record(
        actor_type=actor.type, actor_id=actor.id, action=action, resource=resource,
        decision="allow" if allowed else "deny", reason=reason,
        metadata={
            k: v for k, v in
            {
                "sponsor": actor.sponsor, "name": actor.name, "on_behalf_of": actor.on_behalf_of,
                "via": list(actor.via), **(extra or {}),
            }.items() if v
        },
    )


def _scope_violation(allowed: bool, reason: str, result: dict, needs: str) -> dict | None:
    """A valid delegated token that was refused only for want of a scope is a
    violation worth its own flag in the audit trail: someone reached past what
    they were handed."""
    if allowed or not reason.startswith("insufficient_scope"):
        return None
    return {"violation": "scope", "needs": needs, "granted": result.get("scope", "")}


def _note_agent(actor: oidc_client.Actor) -> None:
    """Keep the app's own record of each agent it has seen."""
    if actor.type != "agent":
        return
    now = time.time()
    conn.execute(
        "INSERT INTO agents (client_id, name, sponsor_sub, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(client_id) DO UPDATE SET last_seen = excluded.last_seen, name = excluded.name, "
        "sponsor_sub = excluded.sponsor_sub",
        (actor.id, actor.name or actor.id, actor.sponsor, now, now),
    )
    conn.commit()


class ReportCreate(BaseModel):
    title: str
    body: str


@app.post("/agent/reports", status_code=201)
def create_report(payload: ReportCreate, request: Request):
    """Agents leave their results here for humans to read. Only an agent's
    token may write; a job's or a person's, even with the scope, may not."""
    token = _bearer_token(request)
    if token is None:
        audit_log.record(
            actor_type="agent", actor_id="anonymous", action="write_report", resource="/agent/reports",
            decision="deny", reason="no bearer token presented",
        )
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    allowed, reason = oidc_client.service_token_allowed(result, "reports:write")
    actor = oidc_client.actor_from_token(result)
    if allowed and actor.type != "agent":
        allowed, reason = False, "only an agent may write reports"
    _audit_actor(actor, "write_report", "/agent/reports", allowed, reason)
    if not allowed:
        raise HTTPException(status_code=401 if not result.get("active") else 403, detail=reason)
    _note_agent(actor)
    cur = conn.execute(
        "INSERT INTO agent_reports (agent_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (actor.id, payload.title, payload.body, time.time()),
    )
    conn.commit()
    return {"id": cur.lastrowid, "agent_id": actor.id}


@app.get("/agent/reports")
def list_reports(
    admin: sqlite3.Row = Depends(require_role("admin", action="list_reports", resource="agent_reports")),
):
    rows = conn.execute("SELECT * FROM agent_reports ORDER BY id DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


# --- lab 08: the tool gateway ------------------------------------------------
#
# Lab 07 let an agent call the API with a scope. Now every tool an agent uses
# goes through one door. The gateway authenticates the token, asks OPA whether
# this agent may make this call with these arguments, records the answer with
# the policy that gave it, and only then does the work.

class ToolCall(BaseModel):
    args: dict[str, str] = {}
    # Lab 10: the second time an agent makes an elevated call, it names the
    # approval a person gave and presents the token that came with it.
    approval_id: int | None = None
    approval_token: str | None = None


def _tool_get_stats(args: dict[str, str]) -> dict:
    users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    notes = conn.execute("SELECT COUNT(*) AS n FROM notes").fetchone()["n"]
    return {"users": users, "notes": notes}


def _tool_write_report(args: dict[str, str], agent_id: str) -> dict:
    cur = conn.execute(
        "INSERT INTO agent_reports (agent_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (agent_id, args.get("title", ""), args.get("body", ""), time.time()),
    )
    conn.commit()
    return {"id": cur.lastrowid, "agent_id": agent_id}


def _tool_list_users(args: dict[str, str]) -> dict:
    rows = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    return {"users": [dict(r) for r in rows]}


def _tool_purge_reports(args: dict[str, str]) -> dict:
    """Delete every report except the newest `keep_latest`. Elevated: it cannot
    be undone, which is why the policy sends it to a person first."""
    keep = int(args["keep_latest"])
    cur = conn.execute(
        "DELETE FROM agent_reports WHERE id NOT IN (SELECT id FROM agent_reports ORDER BY id DESC LIMIT ?)", (keep,),
    )
    conn.commit()
    return {"deleted": cur.rowcount, "kept": keep}


def _bad_tool_args(tool_name: str, args: dict[str, str]) -> str | None:
    """Arguments that make no sense are refused before a person is ever asked
    to approve them."""
    if tool_name == "purge_reports" and not args.get("keep_latest", "").isdigit():
        return "purge_reports needs keep_latest, a whole number of reports to keep"
    return None


def _run_tool(tool_name: str, args: dict[str, str], actor: oidc_client.Actor) -> dict:
    if tool_name == "get_stats":
        return _tool_get_stats(args)
    if tool_name == "write_report":
        return _tool_write_report(args, actor.id)
    if tool_name == "purge_reports":
        return _tool_purge_reports(args)
    return _tool_list_users(args)


TOOL_NAMES = {"get_stats", "write_report", "list_users", "purge_reports"}


@app.post("/agent/tools/{tool_name}")
def call_tool(tool_name: str, payload: ToolCall, request: Request):
    """The one door for agent tool calls. A person's session and a plain
    service's token are both refused here: this door is for agents."""
    token = _bearer_token(request)
    if token is None:
        audit_log.record(
            actor_type="agent", actor_id="anonymous", action=tool_name, resource=f"tool:{tool_name}",
            decision="deny", reason="no bearer token presented",
        )
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    actor = oidc_client.actor_from_token(result)
    if not result.get("active"):
        _audit_actor(actor, tool_name, f"tool:{tool_name}", False, "token is not active (expired, revoked or invalid)")
        raise HTTPException(status_code=401, detail="token is not active")
    if actor.type != "agent":
        _audit_actor(actor, tool_name, f"tool:{tool_name}", False, "only an agent may call tools here")
        raise HTTPException(status_code=403, detail="only an agent may call tools here")
    _note_agent(actor)
    if tool_name not in TOOL_NAMES:
        _audit_actor(actor, tool_name, f"tool:{tool_name}", False, f"unknown tool '{tool_name}'")
        raise HTTPException(status_code=404, detail=f"unknown tool '{tool_name}'")

    decision = opa_client.decide(opa_client.build_input(actor, result, tool_name, payload.args))
    meta = {"sponsor": actor.sponsor, "name": actor.name, "policies": list(decision.policies), "engine": "opa"}
    if not decision.allow:
        audit_log.record(
            actor_type="agent", actor_id=actor.id, action=tool_name, resource=f"tool:{tool_name}",
            decision="deny", reason="; ".join(decision.reasons), metadata=meta,
        )
        raise HTTPException(status_code=403, detail=decision.summary)
    bad = _bad_tool_args(tool_name, payload.args)
    if bad:
        audit_log.record(
            actor_type="agent", actor_id=actor.id, action=tool_name, resource=f"tool:{tool_name}",
            decision="deny", reason=bad, metadata=meta,
        )
        raise HTTPException(status_code=400, detail=bad)

    if decision.requires_approval:
        gated = _approval_gate(actor, tool_name, payload, meta)
        if gated is not None:
            return gated
    else:
        audit_log.record(
            actor_type="agent", actor_id=actor.id, action=tool_name, resource=f"tool:{tool_name}",
            decision="allow", reason="; ".join(decision.reasons), metadata=meta,
        )
    return _run_tool(tool_name, payload.args, actor)


# --- lab 10: the approval gate -------------------------------------------------
#
# The policy has said an elevated call is allowed in principle. It still doesn't
# run. The first attempt becomes a request in a queue, and the agent gets a 202
# and waits. A person approves or denies it. An approval mints a token that is
# good for one minute, for this agent, this tool and these arguments, once. The
# agent repeats the call with the token and only then does the work happen.

def _sweep_approvals() -> None:
    """Move anything that has run out of time to `expired`, and wipe its token.
    Called before every read or decision, so a stale request never looks live."""
    now = time.time()
    for row in conn.execute("SELECT * FROM approvals WHERE status IN ('pending', 'approved')").fetchall():
        if not approvals.is_due(row, now):
            continue
        reason = (
            "nobody decided in time, so the request lapsed" if row["status"] == approvals.PENDING
            else "approved, but the agent did not use the token in time"
        )
        moved = conn.execute(
            "UPDATE approvals SET status = ?, approval_token = NULL WHERE id = ? AND status = ?",
            (approvals.transition(row["status"], "expire"), row["id"], row["status"]),
        )
        conn.commit()
        if moved.rowcount:
            with trace_context(row["trace_id"]):
                audit_log.record(
                    actor_type="service", actor_id="approval-gate", action="approval_expired",
                    resource=f"approval:{row['id']}", decision="deny", reason=reason,
                    metadata={"approval_id": row["id"], "agent": row["agent_id"], "tool": row["tool"]},
                )


def _approval_gate(actor: oidc_client.Actor, tool_name: str, payload: ToolCall, meta: dict):
    """Returns a response to send instead of running the tool, or None when the
    call is approved and should go ahead."""
    resource = f"tool:{tool_name}"
    digest = approvals.args_digest(tool_name, payload.args)
    now = time.time()
    _sweep_approvals()

    if payload.approval_id is None:
        row = conn.execute(
            "SELECT * FROM approvals WHERE agent_id = ? AND tool = ? AND args_digest = ? AND status = 'pending'",
            (actor.id, tool_name, digest),
        ).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO approvals (agent_id, agent_name, sponsor, tool, args_json, args_digest, trace_id, "
                "requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (actor.id, actor.name, actor.sponsor, tool_name, json.dumps(payload.args), digest,
                 current_trace_id(), now, now + approvals.REQUEST_TTL_SECONDS),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (cur.lastrowid,)).fetchone()
            audit_log.record(
                actor_type="agent", actor_id=actor.id, action=tool_name, resource=resource, decision="deny",
                reason="held: a person has to approve this before it runs",
                metadata={**meta, "approval_id": row["id"], "args": payload.args},
            )
        return JSONResponse(status_code=202, content={
            "status": "pending_approval", "approval_id": row["id"], "expires_at": row["expires_at"],
            "poll": f"/agent/approvals/{row['id']}",
        })

    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (payload.approval_id,)).fetchone()
    if row is None:
        allowed, reason = False, "no such approval"
    else:
        allowed, reason = approvals.approval_token_allowed(
            row, payload.approval_token or "", agent_id=actor.id, tool=tool_name, digest=digest, now=now,
        )
    meta = {**meta, "approval_id": payload.approval_id}
    if not allowed:
        audit_log.record(
            actor_type="agent", actor_id=actor.id, action=tool_name, resource=resource, decision="deny",
            reason=f"approval refused: {reason}", metadata=meta,
        )
        raise HTTPException(status_code=403, detail=reason)
    spent = conn.execute(
        "UPDATE approvals SET status = ?, used_at = ?, approval_token = NULL WHERE id = ? AND status = ?",
        (approvals.transition(row["status"], "use"), now, row["id"], approvals.APPROVED),
    )
    conn.commit()
    if not spent.rowcount:
        raise HTTPException(status_code=403, detail="the approval was already used")
    audit_log.record(
        actor_type="agent", actor_id=actor.id, action=tool_name, resource=resource, decision="allow",
        reason=f"approved by {row['decided_by']}; the approval token was spent",
        metadata={**meta, "approved_by": row["decided_by"]},
    )
    return None


@app.get("/agent/approvals/{approval_id}")
def poll_approval(approval_id: int, request: Request):
    """The agent asks how its request is getting on. Once a person has approved,
    the answer carries the token to use. Only the agent that asked can ask."""
    actor = _agent_from_request(request, "poll_approval", f"approval:{approval_id}")
    _sweep_approvals()
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if row is None or row["agent_id"] != actor.id:
        raise HTTPException(status_code=404, detail="no such approval for this agent")
    body = {"id": row["id"], "status": row["status"], "tool": row["tool"], "expires_at": row["expires_at"]}
    if row["status"] == approvals.APPROVED:
        body.update(approval_token=row["approval_token"], token_expires_at=row["token_expires_at"])
    if row["status"] == approvals.DENIED:
        body["note"] = row["decision_note"]
    return body


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern="^(approve|deny)$")
    note: str | None = Field(default=None, max_length=200)


def _approval_view(row: sqlite3.Row, now: float) -> dict:
    """What the queue shows. Never the token: a person decides, the agent
    collects."""
    left = {
        approvals.PENDING: row["expires_at"], approvals.APPROVED: row["token_expires_at"],
    }.get(row["status"])
    return {
        "id": row["id"], "agent_id": row["agent_id"], "agent_name": row["agent_name"], "sponsor": row["sponsor"],
        "tool": row["tool"], "args": json.loads(row["args_json"]), "status": row["status"],
        "requested_at": row["requested_at"], "seconds_left": max(0, left - now) if left else None,
        "decided_by": row["decided_by"], "decided_at": row["decided_at"], "decision_note": row["decision_note"],
        "trace_id": row["trace_id"],
    }


def _decider(session: sqlite3.Row, row: sqlite3.Row) -> tuple[sqlite3.Row, bool, str]:
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    allowed, reason = approvals.may_decide(role=user["role"], idp_sub=user["idp_sub"], sponsor=row["sponsor"])
    return user, allowed, reason


@app.get("/approvals")
def list_approvals(session: sqlite3.Row = Depends(get_current_session)):
    """The pending-approval queue: the requests this person is allowed to decide,
    newest first, with the recently decided ones underneath."""
    _sweep_approvals()
    now = time.time()
    rows = conn.execute("SELECT * FROM approvals ORDER BY id DESC LIMIT 50").fetchall()
    return [_approval_view(r, now) for r in rows if _decider(session, r)[1]]


@app.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: int, payload: ApprovalDecision, session: sqlite3.Row = Depends(get_current_session)):
    _sweep_approvals()
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no such approval")
    user, allowed, reason = _decider(session, row)
    who = user["idp_sub"] or user["username"]
    resource = f"approval:{approval_id}"
    meta = {"approval_id": approval_id, "agent": row["agent_id"], "tool": row["tool"], "sponsor": row["sponsor"]}
    with trace_context(row["trace_id"]):
        if not allowed:
            audit_log.record(
                actor_type="human", actor_id=who, action="decide_approval", resource=resource,
                decision="deny", reason=reason, metadata=meta,
            )
            raise HTTPException(status_code=403, detail=reason)
        try:
            new_status = approvals.transition(row["status"], payload.decision)
        except approvals.InvalidTransition as e:
            audit_log.record(
                actor_type="human", actor_id=who, action="decide_approval", resource=resource,
                decision="deny", reason=str(e), metadata=meta,
            )
            raise HTTPException(status_code=409, detail=str(e)) from e
        now = time.time()
        approved = new_status == approvals.APPROVED
        conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?, "
            "approval_token = ?, token_expires_at = ? WHERE id = ?",
            (new_status, who, now, payload.note, approvals.new_token() if approved else None,
             now + approvals.TOKEN_TTL_SECONDS if approved else None, approval_id),
        )
        conn.commit()
        audit_log.record(
            actor_type="human", actor_id=who, action="decide_approval", resource=resource,
            decision="allow" if approved else "deny",
            reason=f"{'approved' if approved else 'denied'}: {reason}" + (f" ({payload.note})" if payload.note else ""),
            metadata={**meta, "token_ttl_seconds": approvals.TOKEN_TTL_SECONDS} if approved else meta,
        )
    return _approval_view(conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone(), now)


@app.get("/approvals/{approval_id}/trace")
def approval_trace(approval_id: int, session: sqlite3.Row = Depends(get_current_session)):
    """One request's whole story: the agent's ask, the person's decision, the
    spend (or the expiry), all under the trace id of the agent's run."""
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if row is None or not _decider(session, row)[1]:
        raise HTTPException(status_code=404, detail="no such approval")
    events = [e.to_dict() for e in audit_log.by_trace(row["trace_id"]) if e.action != "oidc_introspect"]
    events.sort(key=lambda e: e["ts"])
    return {"trace_id": row["trace_id"], "events": events}


# --- lab 09: acting on behalf of a person --------------------------------------
#
# A person asks the agent to do something for them. The agent never sees their
# password or their session: it is handed their access token for this one task,
# trades it at the IdP for a narrower token that names both of them, and uses
# that token against a downstream API. One trace id follows the request through
# every hop, so the chain can be read back afterwards.

class TaskCreate(BaseModel):
    kind: str = "summarise_notes"


@app.post("/agent/tasks", status_code=201)
def create_task(payload: TaskCreate, session: sqlite3.Row = Depends(get_current_session)):
    """A signed-in person asks the agent to act for them. Only a session that
    came from the Lab IdP has an access token to delegate."""
    if not session["access_token"]:
        raise HTTPException(status_code=400, detail="sign in with the Lab IdP first: there is no access token to delegate")
    if payload.kind not in ("summarise_notes", "archive_notes"):
        raise HTTPException(status_code=400, detail="unknown task kind")
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    trace_id = current_trace_id()
    cur = conn.execute(
        "INSERT INTO agent_tasks (user_id, kind, subject_token, trace_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (user["id"], payload.kind, session["access_token"], trace_id, time.time()),
    )
    conn.commit()
    audit_log.record(
        actor_type="human", actor_id=user["idp_sub"] or str(user["id"]), action="create_agent_task",
        resource=f"task:{cur.lastrowid}", decision="allow", reason="asked the agent to act on their behalf",
        metadata={"task_id": cur.lastrowid, "kind": payload.kind},
    )
    return {"id": cur.lastrowid, "trace_id": trace_id}


def _agent_from_request(request: Request, action: str, resource: str) -> oidc_client.Actor:
    """Authenticate the caller as an agent acting as itself (not for anyone)."""
    token = _bearer_token(request)
    if token is None:
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    actor = oidc_client.actor_from_token(result)
    if not result.get("active"):
        _audit_actor(actor, action, resource, False, "token is not active (expired, revoked or invalid)")
        raise HTTPException(status_code=401, detail="token is not active")
    if actor.type != "agent" or actor.on_behalf_of:
        _audit_actor(actor, action, resource, False, "only an agent acting as itself may do this")
        raise HTTPException(status_code=403, detail="only an agent acting as itself may do this")
    return actor


@app.get("/agent/tasks/next")
def next_task(request: Request, kind: str | None = None):
    """The agent asks for its next job. The answer includes the person's access
    token, which the agent is expected to exchange straight away."""
    actor = _agent_from_request(request, "claim_task", "agent_tasks")
    _note_agent(actor)
    row = conn.execute(
        "SELECT * FROM agent_tasks WHERE status = 'pending' AND (? IS NULL OR kind = ?) ORDER BY id LIMIT 1", (kind, kind),
    ).fetchone()
    if row is None:
        return {"task": None}
    conn.execute("UPDATE agent_tasks SET status = 'claimed', claimed_by = ? WHERE id = ?", (actor.id, row["id"]))
    conn.commit()
    _audit_actor(actor, "claim_task", f"task:{row['id']}", True, "agent claimed a pending task")
    return {"task": {
        "id": row["id"], "kind": row["kind"], "subject_token": row["subject_token"], "trace_id": row["trace_id"],
    }}


@app.post("/agent/tasks/{task_id}/complete")
def complete_task(task_id: int, request: Request):
    """The agent says it is finished. The person's token is wiped from the row:
    it was lent for one task and should not outlive it."""
    actor = _agent_from_request(request, "complete_task", f"task:{task_id}")
    row = conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None or row["claimed_by"] != actor.id:
        _audit_actor(actor, "complete_task", f"task:{task_id}", False, "no such task claimed by this agent")
        raise HTTPException(status_code=404, detail="no such task claimed by this agent")
    conn.execute("UPDATE agent_tasks SET status = 'done', subject_token = NULL WHERE id = ?", (task_id,))
    conn.commit()
    _audit_actor(actor, "complete_task", f"task:{task_id}", True, "task finished, the person's token was discarded")
    return {"id": task_id, "status": "done"}


@app.get("/delegated/notes")
def delegated_notes(request: Request):
    """Stands in for any downstream API an agent might call for a person. It
    takes only a delegated token, and answers with the notes of the person
    behind it, never the agent's own."""
    token = _bearer_token(request)
    if token is None:
        audit_log.record(
            actor_type="agent", actor_id="anonymous", action="read_notes", resource="/delegated/notes",
            decision="deny", reason="no bearer token presented",
        )
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    allowed, reason = oidc_client.delegated_token_allowed(result, "notes:read")
    actor = oidc_client.actor_from_token(result)
    _audit_actor(actor, "read_notes", "/delegated/notes", allowed, reason, _scope_violation(allowed, reason, result, "notes:read"))
    if not allowed:
        raise HTTPException(status_code=401 if not result.get("active") else 403, detail=reason)
    owner = conn.execute("SELECT * FROM users WHERE idp_sub = ?", (result["sub"],)).fetchone()
    rows = conn.execute(
        "SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id", (owner["id"],)
    ).fetchall() if owner else []
    return {"on_behalf_of": result["sub"], "notes": [dict(r) for r in rows]}


@app.delete("/delegated/notes/{note_id}")
def delegated_delete_note(note_id: int, request: Request):
    """The same downstream API, for the one thing that is not harmless: deleting
    one of the person's notes. It needs `notes:write` on a delegated token, and
    it deletes only the note of the person behind the token."""
    resource = f"/delegated/notes/{note_id}"
    token = _bearer_token(request)
    if token is None:
        audit_log.record(
            actor_type="agent", actor_id="anonymous", action="delete_note", resource=resource,
            decision="deny", reason="no bearer token presented",
        )
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    allowed, reason = oidc_client.delegated_token_allowed(result, "notes:write")
    actor = oidc_client.actor_from_token(result)
    extra = _scope_violation(allowed, reason, result, "notes:write")
    if not allowed:
        _audit_actor(actor, "delete_note", resource, False, reason, extra)
        raise HTTPException(status_code=401 if not result.get("active") else 403, detail=reason)
    owner = conn.execute("SELECT * FROM users WHERE idp_sub = ?", (result["sub"],)).fetchone()
    note = conn.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, owner["id"] if owner else -1)).fetchone()
    if note is None:
        _audit_actor(actor, "delete_note", resource, False, "no such note for the person behind this token")
        raise HTTPException(status_code=404, detail="no such note")
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    _audit_actor(actor, "delete_note", resource, True, f"deleted '{note['title']}' for {result['sub']}")
    return {"deleted": note_id, "on_behalf_of": result["sub"]}


# --- lab 11: passing the work on to a second agent --------------------------------
#
# The agent Alice asked can hand part of the job to another agent. It trades its
# delegated token at the IdP for one made for the second agent, then leaves it
# here for that agent to collect. Same pattern as the task queue in lab 09, one
# level down.

class HandOff(BaseModel):
    target: str
    token: str


@app.post("/agent/handoffs", status_code=201)
def create_handoff(payload: HandOff, request: Request):
    actor = _agent_from_request(request, "hand_off_task", f"agent:{payload.target}")
    result = oidc_client.introspect(payload.token)
    if not result.get("active") or not result.get("acting_as"):
        _audit_actor(actor, "hand_off_task", f"agent:{payload.target}", False, "the token to hand over is not an active delegated token")
        raise HTTPException(status_code=400, detail="the token to hand over is not an active delegated token")
    cur = conn.execute(
        "INSERT INTO agent_handoffs (from_agent, to_agent, token, scope, on_behalf_of, trace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (actor.id, payload.target, payload.token, result.get("scope", ""), result["sub"], current_trace_id(), time.time()),
    )
    conn.commit()
    audit_log.record(
        actor_type="agent", actor_id=actor.id, action="hand_off_task", resource=f"agent:{payload.target}", decision="allow",
        reason=f"left a token for {payload.target} with scope: {result.get('scope')}",
        metadata={"sponsor": actor.sponsor, "on_behalf_of": result["sub"], "hand_off_to": payload.target, "scope": result.get("scope")},
    )
    return {"id": cur.lastrowid}


@app.get("/agent/handoffs/next")
def next_handoff(request: Request):
    """The receiving agent asks whether anything has been handed to it. It only
    ever sees hand-offs addressed to it."""
    actor = _agent_from_request(request, "claim_handoff", "agent_handoffs")
    _note_agent(actor)
    row = conn.execute(
        "SELECT * FROM agent_handoffs WHERE status = 'pending' AND to_agent = ? ORDER BY id LIMIT 1", (actor.id,)
    ).fetchone()
    if row is None:
        return {"handoff": None}
    conn.execute("UPDATE agent_handoffs SET status = 'claimed' WHERE id = ?", (row["id"],))
    conn.commit()
    # The claimer couldn't know the trace before it claimed, so record the claim
    # under the trace the work belongs to: the story stays in one place.
    with trace_context(row["trace_id"]):
        _audit_actor(actor, "claim_handoff", f"handoff:{row['id']}", True, f"claimed work handed over by {row['from_agent']}")
    return {"handoff": {
        "id": row["id"], "token": row["token"], "scope": row["scope"], "trace_id": row["trace_id"], "from_agent": row["from_agent"],
    }}


@app.post("/agent/handoffs/{handoff_id}/complete")
def complete_handoff(handoff_id: int, request: Request):
    actor = _agent_from_request(request, "complete_handoff", f"handoff:{handoff_id}")
    row = conn.execute("SELECT * FROM agent_handoffs WHERE id = ?", (handoff_id,)).fetchone()
    if row is None or row["to_agent"] != actor.id or row["status"] != "claimed":
        _audit_actor(actor, "complete_handoff", f"handoff:{handoff_id}", False, "no such hand-off claimed by this agent")
        raise HTTPException(status_code=404, detail="no such hand-off claimed by this agent")
    conn.execute("UPDATE agent_handoffs SET status = 'done', token = NULL WHERE id = ?", (handoff_id,))
    conn.commit()
    _audit_actor(actor, "complete_handoff", f"handoff:{handoff_id}", True, "work finished, the token was discarded")
    return {"id": handoff_id, "status": "done"}


def delegation_chain(events: list[dict]) -> list[dict]:
    """Read a trace back as the chain it records: the person, each agent the
    authority passed through, and the API at the end. Each hop appears once, in
    the order it first showed up, with the API last."""
    chain: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(role: str, who: str, **extra) -> None:
        if (role, who) not in seen:
            seen.add((role, who))
            chain.append({"role": role, "id": who, **extra})

    for e in events:
        md = e.get("metadata") or {}
        if e["action"] == "create_agent_task":
            add("human", e["actor_id"])
        elif e["actor_type"] == "agent" and md.get("on_behalf_of"):
            add("human", md["on_behalf_of"])
            for upstream in md.get("via", []):
                add("agent", upstream, on_behalf_of=md["on_behalf_of"])
            add("agent", e["actor_id"], sponsor=md.get("sponsor"), on_behalf_of=md["on_behalf_of"])
            if e["action"] == "hand_off" and e["decision"] == "allow":
                add("agent", md["hand_off_to"], on_behalf_of=md["on_behalf_of"])
            if e["action"] == "read_notes" and e["decision"] == "allow":
                add("api", e["resource"] or "")
    # The API is where the chain ends, however early it was first reached.
    return [h for h in chain if h["role"] != "api"] + [h for h in chain if h["role"] == "api"]


@app.get("/delegation/trace/{trace_id}")
def delegation_trace(trace_id: str, session: sqlite3.Row = Depends(get_current_session)):
    """One delegated task as a single timeline: the person's request, the
    agent's token exchange at the IdP, and the call to the downstream API, all
    under one trace id. Visible to the person who asked, and to admins."""
    task = conn.execute("SELECT * FROM agent_tasks WHERE trace_id = ?", (trace_id,)).fetchone()
    me = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if task is None or (task["user_id"] != me["id"] and me["role"] != "admin"):
        raise HTTPException(status_code=404, detail="no such delegation trace")
    events = [{**e.to_dict(), "source": "app"} for e in audit_log.by_trace(trace_id)]
    try:
        res = oidc_client._http.get(f"{oidc_client.IDP_URL}/observability/traces/{trace_id}")
        res.raise_for_status()
        events += [{**e, "source": "idp"} for e in res.json()]
    except Exception:
        pass
    # Introspection calls happen on every hop and say nothing about who acted.
    events = [e for e in events if e["action"] != "oidc_introspect"]
    events.sort(key=lambda e: e["ts"])
    return {"trace_id": trace_id, "status": task["status"], "chain": delegation_chain(events), "events": events}


# --- lab 12: one trace, one kill-switch ----------------------------------------
#
# Everything an operator needs to answer "what is this agent doing, and who
# let it" and to stop it: a timeline per trace id across both services and
# every kind of identity, and a switch that cuts an agent off at the IdP.

class KillRequest(BaseModel):
    reason: str = Field(default="", max_length=200)
    trace_id: str | None = None   # the trace being watched, so the cut-off appears in it


def _cut_off_agents() -> dict[str, dict]:
    """What the IdP says is cut off right now. If it can't be reached, say so
    rather than pretend nothing is."""
    try:
        res = oidc_client._http.get(
            f"{oidc_client.IDP_URL}/agents/cut-off", auth=(oidc_client.RESOURCE_SERVER_ID, oidc_client.RESOURCE_SERVER_SECRET),
        )
        res.raise_for_status()
        return {r["client_id"]: r for r in res.json()}
    except Exception:
        return {}


@app.post("/agents/{client_id}/kill")
def kill_agent(client_id: str, payload: KillRequest, session: sqlite3.Row = Depends(get_current_session)):
    """The kill-switch. An admin, or the agent's own sponsor, cuts an agent off:
    the IdP stops honouring every token it holds or has handed on, and anything it
    had waiting is ended. Its next request, to anything, is refused."""
    agent = conn.execute("SELECT * FROM agents WHERE client_id = ?", (client_id,)).fetchone()
    if agent is None:
        raise HTTPException(status_code=404, detail="the app has not seen that agent")
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    who = user["idp_sub"] or user["username"]
    trace = payload.trace_id if payload.trace_id and _TRACE_RE.match(payload.trace_id) else current_trace_id()
    with trace_context(trace):
        allowed, why = approvals.may_decide(role=user["role"], idp_sub=user["idp_sub"], sponsor=agent["sponsor_sub"])
        if not allowed:
            audit_log.record(
                actor_type="human", actor_id=who, action="kill_agent", resource=f"agent:{client_id}",
                decision="deny", reason=why,
            )
            raise HTTPException(status_code=403, detail=why)
        res = oidc_client._http.post(
            f"{oidc_client.IDP_URL}/agents/{client_id}/cut-off", data={"by": who, "reason": payload.reason},
            auth=(oidc_client.RESOURCE_SERVER_ID, oidc_client.RESOURCE_SERVER_SECRET), headers={"X-Trace-Id": trace},
        )
        if res.status_code != 200:
            raise HTTPException(status_code=502, detail="the IdP did not cut the agent off, so nothing was changed here")
        ended = approvals.cut_off_pending_work(conn, client_id, time.time())
        audit_log.record(
            actor_type="human", actor_id=who, action="kill_agent", resource=f"agent:{client_id}", decision="allow",
            reason=f"{client_id} cut off at the IdP; {ended} unfinished item(s) ended" + (f": {payload.reason}" if payload.reason else ""),
            metadata={"agent": client_id, "ended": ended, "sponsor": agent["sponsor_sub"]},
        )
    return {"client_id": client_id, "cut_off": True, "ended": ended}


@app.post("/agents/{client_id}/restore")
def restore_agent(
    client_id: str,
    admin: sqlite3.Row = Depends(require_role("admin", action="restore_agent", resource="agents")),
):
    """Put a cut-off agent back. Admin only: the person who can switch it off
    is not automatically the one who decides it is safe again."""
    res = oidc_client._http.post(
        f"{oidc_client.IDP_URL}/agents/{client_id}/restore", data={"by": admin["username"]},
        auth=(oidc_client.RESOURCE_SERVER_ID, oidc_client.RESOURCE_SERVER_SECRET),
    )
    if res.status_code != 200:
        raise HTTPException(status_code=502, detail="the IdP did not restore the agent")
    audit_log.record(
        actor_type="human", actor_id=admin["username"], action="restore_agent", resource=f"agent:{client_id}",
        decision="allow", reason=f"{client_id} restored",
    )
    return {"client_id": client_id, "cut_off": False}


@app.get("/traces")
def list_traces(
    limit: int = 25,
    admin: sqlite3.Row = Depends(require_role("admin", action="list_traces", resource="traces")),
):
    """The most recent traces the app has logged, each with who took part."""
    return traces.summarise([e.to_dict() for e in audit_log.recent(2000)])[:limit]


@app.get("/traces/{trace_id}")
def get_trace(
    trace_id: str,
    admin: sqlite3.Row = Depends(require_role("admin", action="view_trace", resource="traces")),
):
    """One trace as a single timeline, from both services, whoever took part."""
    if not _TRACE_RE.match(trace_id):
        raise HTTPException(status_code=404, detail="no such trace")
    app_events = [e.to_dict() for e in audit_log.by_trace(trace_id)]
    try:
        res = oidc_client._http.get(f"{oidc_client.IDP_URL}/observability/traces/{trace_id}")
        res.raise_for_status()
        idp_events = res.json()
    except Exception:
        idp_events = []
    events = traces.correlate(trace_id, app_events, idp_events)
    if not events:
        raise HTTPException(status_code=404, detail="no such trace")
    return {"trace_id": trace_id, "participants": traces.participants(events), "chain": delegation_chain(events), "events": events}


@app.get("/agent-activity")
def agent_activity(
    limit: int = 50,
    admin: sqlite3.Row = Depends(require_role("admin", action="view_agent_activity", resource="agent_activity")),
):
    """The agent dashboard's data: every agent the app has seen, and what
    each has tried to do, newest first."""
    cut_off = _cut_off_agents()
    agents = [{**dict(r), "cut_off": r["client_id"] in cut_off} for r in conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()]
    events = [e.to_dict() for e in audit_log.recent(500) if e.actor_type == "agent"][:limit]
    return {"agents": agents, "events": events}


@app.get("/internal/stats")
def internal_stats(request: Request):
    """Aggregate numbers for the nightly digest job. Not for humans: it takes
    a bearer token issued to a service, never a session cookie."""
    token = _bearer_token(request)
    if token is None:
        audit_log.record(
            actor_type="service", actor_id="anonymous", action="service_call", resource="/internal/stats",
            decision="deny", reason="no bearer token presented",
        )
        raise HTTPException(status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"})
    result = oidc_client.introspect(token)
    allowed, reason = oidc_client.service_token_allowed(result, "stats:read")
    actor = oidc_client.actor_from_token(result)
    _audit_actor(actor, "service_call", "/internal/stats", allowed, reason)
    if allowed:
        _note_agent(actor)
    if not allowed:
        raise HTTPException(status_code=401 if not result.get("active") else 403, detail=reason)
    users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    notes = conn.execute("SELECT COUNT(*) AS n FROM notes").fetchone()["n"]
    return {"users": users, "notes": notes}


@app.get("/service-calls")
def service_calls(
    limit: int = 30,
    admin: sqlite3.Row = Depends(require_role("admin", action="view_service_calls", resource="service_calls")),
):
    """Recent service-to-service activity from both sides, newest first: the
    IdP's token decisions and this app's endpoint decisions. Powers the
    admin panel's live view."""
    events = [{**e.to_dict(), "source": "app"} for e in audit_log.recent(300) if e.action == "service_call"]
    try:
        res = oidc_client._http.get(f"{oidc_client.IDP_URL}/observability/events", params={"limit": 300})
        res.raise_for_status()
        events += [
            {**e, "source": "idp"} for e in res.json()
            if e["action"] in ("service_token_issued", "oidc_client_auth")
        ]
    except Exception:
        pass
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:limit]


@app.get("/oidc/token/mine")
def oidc_token_mine(request: Request, session: sqlite3.Row = Depends(get_current_session)):
    """The signed-in user's access token, as the IdP sees it right now: what
    it grants, when it expires, whether it is still active. Never returns the
    token itself."""
    if not session["access_token"]:
        return {"federated": False}
    result = oidc_client.introspect(session["access_token"])
    return {
        "federated": True,
        "active": bool(result.get("active")),
        "scopes": (result.get("scope") or "").split(),
        "expires_at": result.get("exp"),
        "jti_prefix": (session["access_token_jti"] or "")[:8] + "…",
    }


@app.post("/oidc/token/revoke")
def oidc_token_revoke(session: sqlite3.Row = Depends(get_current_session)):
    """Revoke the access token behind this session. The session itself is
    left in place on purpose: the next request will find the token dead and
    end it, which is the point of checking with the IdP every time."""
    if not session["access_token"]:
        raise HTTPException(status_code=400, detail="this session did not come from the Lab IdP")
    oidc_client.revoke(session["access_token"])
    audit_log.record(
        actor_type="human", actor_id=str(session["user_id"]), action="revoke_token",
        resource="access_token", decision="allow", reason="user revoked their own access token",
    )
    return {"revoked": True}


@app.get("/oidc/trace/{trace_id}")
def oidc_trace(trace_id: str):
    """One login attempt as a single timeline: this app's events and the
    IdP's, merged by time. Powers the live redirect and token-exchange trace.

    LAB ONLY (ADR-0008): no authentication here, because a failed login has
    no session to authenticate with and the trace is the thing a learner
    needs to see. It is safe in this lab only because trace ids are 128-bit
    random values and the events never contain the code, the verifier or a
    token. A real system would put this behind an operator login."""
    flow = conn.execute("SELECT * FROM oidc_flows WHERE trace_id = ?", (trace_id,)).fetchone()
    events = [{**e.to_dict(), "source": "client"} for e in audit_log.by_trace(trace_id)]
    idp_reachable = True
    try:
        res = oidc_client._http.get(f"{oidc_client.IDP_URL}/observability/traces/{trace_id}")
        res.raise_for_status()
        events += [{**e, "source": "idp"} for e in res.json()]
    except Exception:
        idp_reachable = False
    events.sort(key=lambda e: e["ts"])
    return {
        "trace_id": trace_id,
        "outcome": flow["outcome"] if flow else None,
        "failure_reason": flow["failure_reason"] if flow else None,
        "id_token_claims": json.loads(flow["id_token_claims_json"]) if flow and flow["id_token_claims_json"] else None,
        "idp_reachable": idp_reachable,
        "events": events,
    }


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
def create_note(
    payload: NoteCreate,
    user: sqlite3.Row = Depends(require_scope("notes:write", action="create_note", resource="notes")),
):
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
def list_my_notes(
    user: sqlite3.Row = Depends(require_scope("notes:read", action="list_notes", resource="notes")),
):
    """Your own notes only — a convenience list so you have IDs to try
    reading/writing as someone else in the panel below, not a general note
    directory."""
    rows = conn.execute(
        "SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],)
    ).fetchall()
    return [_note_row_to_model(r) for r in rows]


@app.get("/notes/{note_id}", response_model=NoteDecision)
def read_note(
    note_id: int,
    user: sqlite3.Row = Depends(require_scope("notes:read", action="read_note", resource="notes")),
):
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
def update_note(
    note_id: int,
    payload: NoteUpdate,
    user: sqlite3.Row = Depends(require_scope("notes:write", action="update_note", resource="notes")),
):
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
