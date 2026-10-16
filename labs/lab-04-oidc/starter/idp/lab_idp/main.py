"""The Lab IdP: a teaching-grade OpenID Provider (ADR-0004).

LAB ONLY, NEVER DEPLOY (ADR-0008). It serves its own login page, issues
authorization codes, and trades them for RS256-signed ID and access tokens
when the client proves it started the flow (PKCE). Run it on localhost:9000.
"""

import html
import os
import re
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from observability_harness import AuditLog, trace_context
from observability_harness.dashboard import create_dashboard_router

from . import keys, oauth
from .db import DB_PATH, get_connection
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ISSUER = os.environ.get("LAB_IDP_ISSUER", "http://localhost:9000")

app = FastAPI(title="Lab IdP (teaching only, never deploy)")

conn = get_connection()
audit_log = AuditLog(str(DB_PATH))
signing_key = keys.load_or_create()
app.include_router(create_dashboard_router(audit_log), prefix="/observability")

_hasher = PasswordHasher()
_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")

# ADR-0008: fixed, checked-in credentials so the lab works with zero setup.
SEED_USERS = [
    ("idp-alice", "alice", "Alice Lab", "alice-lab-pass"),
    ("idp-bob", "bob", "Bob Lab", "bob-lab-pass"),
    ("idp-carol", "carol", "Carol Lab", "carol-lab-pass"),
]


def _seed() -> None:
    for sub, username, display, password in SEED_USERS:
        if conn.execute("SELECT 1 FROM idp_users WHERE sub = ?", (sub,)).fetchone():
            continue
        conn.execute(
            "INSERT INTO idp_users (sub, username, password_hash, display_name) VALUES (?, ?, ?, ?)",
            (sub, username, _hasher.hash(password), display),
        )
    conn.commit()


_seed()


@app.middleware("http")
async def bind_trace(request: Request, call_next):
    """Continue the client's trace when it sends one (header on the
    back-channel, query parameter on the browser redirect). This is a lab
    convenience, not part of OIDC: it lets the trace viewer show both
    services' events as one timeline."""
    candidate = request.headers.get("x-trace-id") or request.query_params.get("trace_id")
    trace_id = candidate if candidate and _TRACE_RE.match(candidate) else None
    with trace_context(trace_id):
        return await call_next(request)


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/jwks.json")
def jwks():
    return signing_key.jwks()


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Lab IdP sign in</title>
<style>
 body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 3rem auto; padding: 0 1rem; }}
 .banner {{ background: #fff3cd; border: 1px solid #e0c36a; padding: .5rem .75rem; border-radius: 6px; font-size: 14px; }}
 label {{ display: block; margin-top: .75rem; }} input {{ width: 100%; padding: .4rem; box-sizing: border-box; }}
 button {{ margin-top: 1rem; padding: .5rem 1rem; }} .err {{ color: #b3261e; }}
</style></head><body>
<p class="banner">Lab IdP: a teaching identity provider. Never use it for real accounts.</p>
<h1>Sign in</h1>
<p>The app <b>{client}</b> wants to know who you are.</p>
{error}
<form method="post" action="/authorize/login?{trace_qs}">
{hidden}
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
<p style="font-size:13px;color:#555">Lab accounts: alice, bob, carol (password: &lt;name&gt;-lab-pass)</p>
</body></html>"""

_FLOW_FIELDS = ("client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "scope", "trace_id")


def _redirect_error(redirect_uri: str, state: str | None, error: str, description: str) -> RedirectResponse:
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


def _login_page(flow: dict, error: str | None = None, status: int = 200) -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{k}" value="{html.escape(flow.get(k) or "", quote=True)}">' for k in _FLOW_FIELDS
    )
    client = oauth.CLIENTS[flow["client_id"]]["name"]
    body = _PAGE.format(
        client=html.escape(client),
        error=f'<p class="err">{html.escape(error)}</p>' if error else "",
        hidden=hidden,
        trace_qs=urlencode({"trace_id": flow.get("trace_id") or ""}),
    )
    return HTMLResponse(body, status_code=status)


def _validate_authorize(flow: dict):
    """Return an HTMLResponse/RedirectResponse if the request is invalid,
    otherwise None. A bad client_id or redirect_uri is never redirected to:
    sending an error to an unverified URI would make the IdP an open
    redirector."""
    client = oauth.CLIENTS.get(flow.get("client_id") or "")
    if client is None:
        return HTMLResponse("Unknown client_id.", status_code=400)
    if flow.get("redirect_uri") not in client["redirect_uris"]:
        return HTMLResponse("redirect_uri is not registered for this client.", status_code=400)
    redirect_uri, state = flow["redirect_uri"], flow.get("state")
    if flow.get("response_type", "code") != "code":
        return _redirect_error(redirect_uri, state, "unsupported_response_type", "only response_type=code")
    if not flow.get("code_challenge"):
        return _redirect_error(redirect_uri, state, "invalid_request", "code_challenge is required (PKCE)")
    if flow.get("code_challenge_method") != "S256":
        return _redirect_error(redirect_uri, state, "invalid_request", "code_challenge_method must be S256")
    return None


@app.get("/authorize")
def authorize(
    request: Request,
    client_id: str = "",
    redirect_uri: str = "",
    response_type: str = "code",
    state: str | None = None,
    nonce: str | None = None,
    scope: str = "openid",
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    trace_id: str | None = None,
):
    flow = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": response_type,
        "state": state, "nonce": nonce, "scope": scope, "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method, "trace_id": trace_id,
    }
    problem = _validate_authorize(flow)
    if problem is not None:
        audit_log.record(
            actor_type="service", actor_id=client_id or "unknown", action="oidc_authorize",
            resource="/authorize", decision="deny", reason=f"invalid authorize request (HTTP {problem.status_code})",
        )
        return problem
    audit_log.record(
        actor_type="service", actor_id=client_id, action="oidc_authorize", resource="/authorize",
        decision="allow", reason="authorize request valid, showing login page",
        metadata={"code_challenge_method": code_challenge_method, "has_nonce": bool(nonce)},
    )
    return _login_page(flow)


@app.post("/authorize/login")
def authorize_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    state: str = Form(""),
    nonce: str = Form(""),
    scope: str = Form("openid"),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    trace_id: str = Form(""),
):
    flow = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "state": state or None, "nonce": nonce or None, "scope": scope,
        "code_challenge": code_challenge or None, "code_challenge_method": code_challenge_method or None,
        "trace_id": trace_id or None,
    }
    problem = _validate_authorize(flow)
    if problem is not None:
        return problem

    user = conn.execute("SELECT * FROM idp_users WHERE username = ?", (username,)).fetchone()
    ok = False
    if user is not None:
        try:
            _hasher.verify(user["password_hash"], password)
            ok = True
        except VerifyMismatchError:
            ok = False
    if not ok:
        audit_log.record(
            actor_type="human", actor_id=username, action="oidc_login", resource="/authorize/login",
            decision="deny", reason="bad credentials",
        )
        return _login_page(flow, error="Wrong username or password.", status=401)

    code = oauth.issue_code(
        conn, client_id=client_id, redirect_uri=redirect_uri, code_challenge=code_challenge,
        nonce=nonce or None, sub=user["sub"], trace_id=trace_id or None,
    )
    audit_log.record(
        actor_type="human", actor_id=user["sub"], action="oidc_login", resource="/authorize/login",
        decision="allow", reason="authenticated at the IdP, authorization code issued",
        metadata={"username": username, "code_ttl_seconds": oauth.CODE_TTL_SECONDS},
    )
    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    client_id: str = Form(""),
    code_verifier: str = Form(""),
):
    if grant_type != "authorization_code":
        audit_log.record(
            actor_type="service", actor_id=client_id or "unknown", action="oidc_token_exchange",
            resource="/token", decision="deny", reason=f"unsupported grant_type {grant_type!r}",
        )
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    try:
        row = oauth.redeem_code(
            conn, code=code, client_id=client_id, redirect_uri=redirect_uri, code_verifier=code_verifier,
        )
    except oauth.TokenError as e:
        audit_log.record(
            actor_type="service", actor_id=client_id or "unknown", action="oidc_token_exchange",
            resource="/token", decision="deny", reason=e.reason,
        )
        # The wire response is deliberately vague; only the audit log is specific.
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    user = conn.execute("SELECT * FROM idp_users WHERE sub = ?", (row["sub"],)).fetchone()
    tokens = oauth.mint_tokens(signing_key, issuer=ISSUER, user=user, client_id=client_id, nonce=row["nonce"])
    audit_log.record(
        actor_type="service", actor_id=client_id, action="oidc_token_exchange", resource="/token",
        decision="allow", reason="PKCE verified, tokens issued",
        metadata={"sub": row["sub"], "id_token_ttl_seconds": oauth.ID_TOKEN_TTL_SECONDS},
    )
    return JSONResponse(tokens, headers={"Cache-Control": "no-store"})
