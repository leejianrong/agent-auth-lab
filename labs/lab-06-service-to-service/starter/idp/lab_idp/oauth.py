"""The OAuth 2.0 authorization-code + PKCE core of the Lab IdP.

LAB ONLY (ADR-0004, ADR-0008): this is a teaching IdP. It implements just
enough of RFC 6749, RFC 7636 (PKCE) and OpenID Connect Core to drive the
rest of the course. It is not spec-complete and must never front a real
user base.
"""

import base64
import hashlib
import hmac
import secrets
import sqlite3
import time

import jwt

from .keys import SigningKey

CODE_TTL_SECONDS = 60
ID_TOKEN_TTL_SECONDS = 5 * 60
ACCESS_TOKEN_TTL_SECONDS = 15 * 60

# One registered user-facing client. Lab 05 added scopes and consent
# per client; lab 06 adds a confidential client with credentials.
CLIENTS = {
    "lab-client": {
        "name": "Lab capstone app",
        "redirect_uris": ["http://localhost:8000/auth/oidc/callback"],
    }
}

# Lab 05: a resource server is the thing that receives access tokens and has
# to decide whether to honour them. It authenticates to the introspection
# endpoint with its own credentials (RFC 7662 section 2.1).
# ADR-0008: fixed, checked-in, localhost-only secret.
RESOURCE_SERVERS = {
    "lab-resource-server": "lab-resource-server-secret-do-not-reuse",
}

# Lab 06: service clients act for themselves, with no human present. Each has
# a secret (stored only as a SHA-256 hash, as you would a real credential) and
# an allow-list of scopes it may ever be granted, however much it asks for.
# ADR-0008: the demo secret is fixed, checked in and localhost-only.
SERVICE_CLIENTS = {
    "digest-service": {
        "name": "Nightly digest job",
        "secret_sha256": hashlib.sha256(b"digest-service-secret-do-not-reuse").hexdigest(),
        "allowed_scopes": {"stats:read"},
    }
}
SERVICE_TOKEN_TTL_SECONDS = 5 * 60

# What an app can ask for, in the words the consent screen shows the user.
SCOPES = {
    "openid": "Know who you are (required to sign in)",
    "profile": "See your name and username",
    "notes:read": "Read your notes",
    "notes:write": "Create and edit your notes",
    "stats:read": "Read aggregate statistics (service clients only)",
}
REQUIRED_SCOPES = {"openid"}


def s256_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Does `code_verifier` hash to the `code_challenge` the client sent when
    it started the flow? This is the one check that stops someone who stole
    the authorization code from redeeming it."""
    return hmac.compare_digest(s256_challenge(code_verifier), code_challenge)


def parse_scopes(raw: str | None) -> set[str]:
    """Scopes travel as one space-delimited string (RFC 6749 section 3.3)."""
    return {part for part in (raw or "").split() if part}


def needs_consent(previously_granted: set[str], requested: set[str]) -> bool:
    """Show the consent screen unless the user already agreed to everything
    the app is asking for now. Asking for one new scope is enough to prompt
    again, which is what "incremental consent" means."""
    return not requested <= previously_granted


def granted_scopes(requested: set[str], approved: set[str]) -> set[str]:
    """Which scopes does the app actually get? Only ones it asked for, the
    user approved, and this IdP knows about. `openid` is always included when
    requested: without it there is no sign-in to consent to."""
    allowed = {s for s in requested if s in SCOPES}
    return {s for s in allowed if s in approved or s in REQUIRED_SCOPES}


def authenticate_client(client_id: str, presented_secret: str) -> bool:
    """Is this a registered service client presenting its real secret?"""
    # TODO(lab-06): this lets in anyone who knows a service client's id, which
    # is not a secret (it appears in logs and URLs). Check the presented secret
    # too: hash it with SHA-256 and compare it to the client's stored
    # `secret_sha256`, using a constant-time comparison.
    return client_id in SERVICE_CLIENTS


def scopes_for_service(client_id: str, requested: set[str]) -> set[str]:
    """Which of the requested scopes may this service client actually hold?"""
    # TODO(lab-06): this grants whatever the service asks for, so a compromised
    # digest job could ask for `notes:write` and get it. A service client's
    # permissions come from what it was registered for (`allowed_scopes`),
    # never from what it requests at run time. Narrow the request to that list.
    return set(requested)


def mint_service_token(key: SigningKey, *, issuer: str, client_id: str, scope: str) -> dict:
    """An access token for a service acting as itself. There is no user, so
    `sub` is the client's own id, which is also how a resource server tells it
    apart from a token issued on a human's behalf."""
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": client_id,
        "aud": issuer,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + SERVICE_TOKEN_TTL_SECONDS,
        "jti": secrets.token_hex(8),
    }
    token = jwt.encode(claims, key.private_pem, algorithm="RS256", headers={"kid": key.kid})
    return {"access_token": token, "token_type": "Bearer", "expires_in": SERVICE_TOKEN_TTL_SECONDS, "scope": scope}


def is_revoked(conn: sqlite3.Connection, jti: str) -> bool:
    """Has the token with this `jti` been revoked?"""
    return conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone() is not None


def revoke_token(conn: sqlite3.Connection, jti: str) -> None:
    conn.execute("INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)", (jti, time.time()))
    conn.commit()


def issue_code(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    nonce: str | None,
    sub: str,
    trace_id: str | None,
    scope: str = "openid",
) -> str:
    code = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, nonce, sub, trace_id, scope, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (code, client_id, redirect_uri, code_challenge, nonce, sub, trace_id, scope, time.time() + CODE_TTL_SECONDS),
    )
    conn.commit()
    return code


class TokenError(Exception):
    """An OAuth `invalid_grant` style failure. `reason` is recorded in the
    audit log; the HTTP response only ever says `invalid_grant`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def redeem_code(
    conn: sqlite3.Connection,
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> sqlite3.Row:
    """Validate an authorization code for the token endpoint and mark it
    used. Raises `TokenError` for anything wrong, naming the specific
    reason so the audit trail can show it."""
    row = conn.execute("SELECT * FROM auth_codes WHERE code = ?", (code,)).fetchone()
    if row is None:
        raise TokenError("unknown authorization code")
    if row["used"]:
        raise TokenError("authorization code already used")
    # Burn the code before checking anything else: a code that fails any
    # check below is dead too, so a thief gets exactly one guess.
    conn.execute("UPDATE auth_codes SET used = 1 WHERE code = ?", (code,))
    conn.commit()
    if row["expires_at"] < time.time():
        raise TokenError("authorization code expired")
    if row["client_id"] != client_id:
        raise TokenError("code was issued to a different client")
    if row["redirect_uri"] != redirect_uri:
        raise TokenError("redirect_uri does not match the authorize request")
    if not verify_pkce(code_verifier, row["code_challenge"]):
        raise TokenError("PKCE mismatch: code_verifier does not match code_challenge")
    return row


def mint_tokens(
    key: SigningKey, *, issuer: str, user: sqlite3.Row, client_id: str, nonce: str | None, scope: str = "openid",
) -> dict:
    now = int(time.time())
    id_claims = {
        "iss": issuer,
        "sub": user["sub"],
        "aud": client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL_SECONDS,
        "preferred_username": user["username"],
        "name": user["display_name"],
    }
    if nonce:
        id_claims["nonce"] = nonce
    access_claims = {
        "iss": issuer,
        "sub": user["sub"],
        "aud": issuer,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "jti": secrets.token_hex(8),
    }
    headers = {"kid": key.kid}
    return {
        "id_token": jwt.encode(id_claims, key.private_pem, algorithm="RS256", headers=headers),
        "access_token": jwt.encode(access_claims, key.private_pem, algorithm="RS256", headers=headers),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
    }


def introspect_token(conn: sqlite3.Connection, key: SigningKey, issuer: str, token: str) -> dict:
    """RFC 7662 token introspection: is this access token still good, and
    what does it grant? Anything wrong answers `{"active": false}` and
    nothing else, so a caller learns nothing about why."""
    try:
        claims = jwt.decode(token, key.private_key.public_key(), algorithms=["RS256"], audience=issuer, issuer=issuer)
    except jwt.InvalidTokenError:
        return {"active": False}
    if is_revoked(conn, claims.get("jti", "")):
        return {"active": False}
    return {
        "active": True,
        "scope": claims.get("scope", ""),
        "sub": claims["sub"],
        "client_id": claims.get("client_id"),
        "iss": claims["iss"],
        "exp": claims["exp"],
        "iat": claims["iat"],
        "jti": claims["jti"],
        "token_type": "Bearer",
    }
