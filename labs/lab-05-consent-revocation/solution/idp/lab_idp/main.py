"""The Lab IdP: a teaching-grade OpenID Provider (ADR-0004).

LAB ONLY, NEVER DEPLOY (ADR-0008). It serves its own login page, issues
authorization codes, and trades them for RS256-signed ID and access tokens
when the client proves it started the flow (PKCE). Run it on localhost:9000.
"""

import base64
import html
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import jwt
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
        "introspection_endpoint": f"{ISSUER}/introspect",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "scopes_supported": sorted(oauth.SCOPES),
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

    requested = oauth.parse_scopes(scope)
    prior = _prior_consent(user["sub"], client_id)
    if oauth.needs_consent(prior, requested):
        audit_log.record(
            actor_type="human", actor_id=user["sub"], action="oidc_login", resource="/authorize/login",
            decision="allow", reason="authenticated at the IdP, asking for consent before issuing a code",
            metadata={"username": username, "requested": sorted(requested), "already_granted": sorted(prior)},
        )
        return _consent_page(flow, user, requested, prior)
    audit_log.record(
        actor_type="human", actor_id=user["sub"], action="oidc_login", resource="/authorize/login",
        decision="allow", reason="authenticated at the IdP, consent already on file",
        metadata={"username": username, "already_granted": sorted(prior)},
    )
    return _issue_and_redirect(flow, user, oauth.granted_scopes(requested, prior), reason="authenticated and already consented")


def _prior_consent(sub: str, client_id: str) -> set[str]:
    row = conn.execute("SELECT scopes FROM consents WHERE sub = ? AND client_id = ?", (sub, client_id)).fetchone()
    return oauth.parse_scopes(row["scopes"]) if row else set()


def _issue_and_redirect(flow: dict, user, scopes: set[str], *, reason: str) -> RedirectResponse:
    scope_str = " ".join(sorted(scopes))
    code = oauth.issue_code(
        conn, client_id=flow["client_id"], redirect_uri=flow["redirect_uri"], code_challenge=flow["code_challenge"],
        nonce=flow.get("nonce"), sub=user["sub"], trace_id=flow.get("trace_id"), scope=scope_str,
    )
    audit_log.record(
        actor_type="human", actor_id=user["sub"], action="oidc_code_issued", resource="/authorize",
        decision="allow", reason=f"{reason}, authorization code issued",
        metadata={"granted_scopes": sorted(scopes), "code_ttl_seconds": oauth.CODE_TTL_SECONDS},
    )
    params = {"code": code}
    if flow.get("state"):
        params["state"] = flow["state"]
    return RedirectResponse(f"{flow['redirect_uri']}?{urlencode(params)}", status_code=302)


def _login_ticket(sub: str) -> str:
    """Proof, carried in the consent form, that this browser just passed the
    password check. Signed by the IdP and good for two minutes, so the
    consent step doesn't need a session cookie of its own."""
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": "lab-idp-login-ticket", "sub": sub, "iat": now, "exp": now + 120},
        signing_key.private_pem, algorithm="RS256",
    )


def _ticket_sub(ticket: str) -> str | None:
    try:
        return jwt.decode(
            ticket, signing_key.private_key.public_key(), algorithms=["RS256"],
            audience="lab-idp-login-ticket", issuer=ISSUER,
        )["sub"]
    except jwt.InvalidTokenError:
        return None


_CONSENT_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Lab IdP consent</title>
<style>
 body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }}
 .banner {{ background: #fff3cd; border: 1px solid #e0c36a; padding: .5rem .75rem; border-radius: 6px; font-size: 14px; }}
 li {{ list-style: none; margin: .4rem 0; }} .new {{ background: #e8f0fe; border-radius: 4px; padding: 0 .35rem; font-size: 12px; }}
 button {{ margin-top: 1rem; padding: .5rem 1rem; }}
</style></head><body>
<p class="banner">Lab IdP: a teaching identity provider. Never use it for real accounts.</p>
<h1>Allow access?</h1>
<p><b>{client}</b> is asking to act for <b>{user}</b>. Untick anything you don't want to share.</p>
<form method="post" action="/authorize/consent?{trace_qs}">
{hidden}
<ul>{boxes}</ul>
<button type="submit" name="decision" value="allow">Allow selected</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></body></html>"""


def _consent_page(flow: dict, user, requested: set[str], prior: set[str]) -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{k}" value="{html.escape(flow.get(k) or "", quote=True)}">' for k in _FLOW_FIELDS
    ) + f'\n<input type="hidden" name="login_ticket" value="{html.escape(_login_ticket(user["sub"]), quote=True)}">'
    boxes = []
    for name in sorted(requested, key=lambda n: (n not in oauth.REQUIRED_SCOPES, n)):
        if name not in oauth.SCOPES:
            continue
        required = name in oauth.REQUIRED_SCOPES
        flag = "" if name in prior else ' <span class="new">new</span>'
        boxes.append(
            f'<li><label><input type="checkbox" name="approve" value="{html.escape(name)}" checked'
            f'{" disabled" if required else ""}> <code>{html.escape(name)}</code>: '
            f'{html.escape(oauth.SCOPES[name])}{flag}</label></li>'
        )
    body = _CONSENT_PAGE.format(
        client=html.escape(oauth.CLIENTS[flow["client_id"]]["name"]), user=html.escape(user["username"]),
        hidden=hidden, boxes="".join(boxes), trace_qs=urlencode({"trace_id": flow.get("trace_id") or ""}),
    )
    return HTMLResponse(body)


@app.post("/authorize/consent")
async def authorize_consent(request: Request):
    form = await request.form()
    flow = {k: (form.get(k) or None) for k in _FLOW_FIELDS}
    flow["response_type"] = "code"
    problem = _validate_authorize(flow)
    if problem is not None:
        return problem
    sub = _ticket_sub(str(form.get("login_ticket") or ""))
    if sub is None:
        audit_log.record(
            actor_type="human", actor_id="unknown", action="oidc_consent", resource="/authorize/consent",
            decision="deny", reason="login ticket missing, invalid or expired",
        )
        return HTMLResponse("Your sign-in expired. Start again from the app.", status_code=400)
    user = conn.execute("SELECT * FROM idp_users WHERE sub = ?", (sub,)).fetchone()
    if form.get("decision") != "allow":
        audit_log.record(
            actor_type="human", actor_id=sub, action="oidc_consent", resource="/authorize/consent",
            decision="deny", reason="the user denied the request",
        )
        return _redirect_error(flow["redirect_uri"], flow.get("state"), "access_denied", "the user denied the request")

    requested = oauth.parse_scopes(flow.get("scope"))
    approved = {str(v) for v in form.getlist("approve")}
    granted = oauth.granted_scopes(requested, approved)
    conn.execute(
        "INSERT OR REPLACE INTO consents (sub, client_id, scopes, granted_at) VALUES (?, ?, ?, ?)",
        (sub, flow["client_id"], " ".join(sorted(granted)), time.time()),
    )
    conn.commit()
    audit_log.record(
        actor_type="human", actor_id=sub, action="oidc_consent", resource="/authorize/consent",
        decision="allow", reason="the user chose which scopes to share",
        metadata={"requested": sorted(requested), "granted": sorted(granted), "withheld": sorted(requested - granted)},
    )
    return _issue_and_redirect(flow, user, granted, reason="consent given")


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
    tokens = oauth.mint_tokens(
        signing_key, issuer=ISSUER, user=user, client_id=client_id, nonce=row["nonce"], scope=row["scope"],
    )
    audit_log.record(
        actor_type="service", actor_id=client_id, action="oidc_token_exchange", resource="/token",
        decision="allow", reason="PKCE verified, tokens issued",
        metadata={"sub": row["sub"], "scope": row["scope"], "id_token_ttl_seconds": oauth.ID_TOKEN_TTL_SECONDS},
    )
    return JSONResponse(tokens, headers={"Cache-Control": "no-store"})


def _basic_auth(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:]).decode()
        client, _, secret = decoded.partition(":")
        return client, secret
    except Exception:
        return None


@app.post("/introspect")
def introspect(request: Request, token: str = Form("")):
    """RFC 7662. Only a registered resource server may ask, with its own
    credentials; otherwise anyone could probe whether a token is live."""
    creds = _basic_auth(request)
    expected = oauth.RESOURCE_SERVERS.get(creds[0]) if creds else None
    if creds is None or expected is None or not secrets.compare_digest(creds[1], expected):
        audit_log.record(
            actor_type="service", actor_id=creds[0] if creds else "anonymous", action="oidc_introspect",
            resource="/introspect", decision="deny", reason="resource server credentials missing or wrong",
        )
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    result = oauth.introspect_token(conn, signing_key, ISSUER, token)
    audit_log.record(
        actor_type="service", actor_id=creds[0], action="oidc_introspect", resource="/introspect",
        decision="allow" if result["active"] else "deny",
        reason="token is active" if result["active"] else "token is not active (expired, revoked or invalid)",
        metadata={"jti": result.get("jti"), "scope": result.get("scope")} if result["active"] else {},
    )
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/revoke")
def revoke(token: str = Form(""), client_id: str = Form("")):
    """RFC 7009. The client that was issued the token may revoke it. Always
    answers 200: telling a caller "that token never existed" would let them
    probe for valid ones."""
    try:
        claims = jwt.decode(
            token, signing_key.private_key.public_key(), algorithms=["RS256"],
            audience=ISSUER, issuer=ISSUER, options={"verify_exp": False},
        )
    except jwt.InvalidTokenError:
        claims = None
    if claims is not None and claims.get("client_id") == client_id:
        oauth.revoke_token(conn, claims["jti"])
        audit_log.record(
            actor_type="service", actor_id=client_id, action="oidc_revoke", resource="/revoke",
            decision="allow", reason="access token revoked", metadata={"jti": claims["jti"], "sub": claims["sub"]},
        )
    else:
        audit_log.record(
            actor_type="service", actor_id=client_id or "unknown", action="oidc_revoke", resource="/revoke",
            decision="deny", reason="token invalid or issued to a different client",
        )
    return JSONResponse({}, status_code=200)
