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
#
# Lab 07: an agent is a service client with two extra properties. It is marked
# `client_type: "agent"` so everything downstream can tell it from an ordinary
# job, and it names a human `sponsor` who answers for it. Agents also get
# shorter-lived tokens, because what they do next isn't fixed in advance.
#
# Lab 08: an agent also has `capabilities`, the specific tool calls it is
# registered for. A capability names one tool, says which scope it hangs off,
# and may carry limits on how the tool is used (`max_body_chars` caps a
# report's length). The token carries only the capabilities whose scope it was
# actually granted.
SERVICE_CLIENTS = {
    "digest-service": {
        "name": "Nightly digest job",
        "client_type": "service",
        "secret_sha256": hashlib.sha256(b"digest-service-secret-do-not-reuse").hexdigest(),
        "allowed_scopes": {"stats:read"},
    },
    "tidy-agent": {
        "name": "Tidy agent",
        "client_type": "agent",
        "sponsor": "idp-alice",
        "secret_sha256": hashlib.sha256(b"tidy-agent-secret-do-not-reuse").hexdigest(),
        "allowed_scopes": {"stats:read", "reports:write"},
        "capabilities": [
            {"tool": "get_stats", "scope": "stats:read"},
            {"tool": "write_report", "scope": "reports:write", "max_body_chars": 200},
        ],
        # Lab 09: the most this agent can ever do on behalf of a person, however
        # much that person has agreed to. Delegation can only narrow, so the
        # scopes on a delegated token are the overlap of three lists.
        "delegable_scopes": {"notes:read"},
    },
}
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
SERVICE_TOKEN_TTL_SECONDS = 5 * 60
AGENT_TOKEN_TTL_SECONDS = 2 * 60

# What an app can ask for, in the words the consent screen shows the user.
SCOPES = {
    "openid": "Know who you are (required to sign in)",
    "profile": "See your name and username",
    "notes:read": "Read your notes",
    "notes:write": "Create and edit your notes",
    "stats:read": "Read aggregate statistics (service clients only)",
    "reports:write": "Write reports (agents only)",
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
    client = SERVICE_CLIENTS.get(client_id)
    if client is None:
        return False
    presented = hashlib.sha256(presented_secret.encode()).hexdigest()
    return hmac.compare_digest(presented, client["secret_sha256"])


def scopes_for_service(client_id: str, requested: set[str]) -> set[str]:
    """Which of the requested scopes may this service client actually hold?"""
    return requested & SERVICE_CLIENTS[client_id]["allowed_scopes"]


def capabilities_for_scopes(capabilities: list[dict], granted: set[str]) -> list[dict]:
    """Which of a client's registered capabilities belong on a token that was
    granted `granted`? A capability is only as good as the scope it hangs off:
    asking for fewer scopes has to mean fewer capabilities. The `scope` key is
    registration detail, so it is left off what goes into the token."""
    return [{k: v for k, v in cap.items() if k != "scope"} for cap in capabilities if cap["scope"] in granted]


def narrow_delegated_scope(subject_scope: set[str], requested: set[str], delegable: set[str]) -> set[str]:
    """Which scopes may a delegated token carry? An agent acting for a person
    can never hold more than the person has, and never more than the agent was
    registered to be trusted with, whatever it asks for."""
    # TODO(lab-09): this hands over whatever the agent asks for that it is
    # registered for, even if the person never agreed to it at the consent
    # screen. An agent that is trusted to read notes could then read the
    # notes of someone who only shared their profile. A delegated token may
    # carry only scopes that are in all three sets: requested, held by the
    # person (`subject_scope`), and delegable by this agent.
    return requested & delegable


def compose_delegated_claims(
    subject: dict, *, agent_id: str, agent_name: str, sponsor: str | None, scope: str,
    issuer: str, now: int, ttl: int,
) -> dict:
    """The claims of a token an agent holds while acting for a person (the
    idea of RFC 8693 token exchange). `subject` is the introspected token of
    the person, as returned by `introspect_token`.

    The token has to say two things at once, and downstream services need both:
    whose authority this is, and who is exercising it."""
    # TODO(lab-09): this issues the agent a token of its own with the notes
    # scope, so the person has vanished from it: a downstream API sees only
    # "tidy-agent" and cannot tell whose notes are being read. Build the
    # delegated claims instead. `sub` stays the person's (`subject["sub"]`).
    # Add `acting_as`: an object with the agent's id as `sub` and its
    # `sponsor`. `client_id` is the agent. `exp` is the sooner of now + ttl and
    # the person's own token expiry (`subject["exp"]`), so a delegation never
    # outlives the authority behind it. Keep the claims the other tokens have
    # (iss, aud, iat, jti, client_type, client_name, sponsor, scope).
    return {
        "iss": issuer, "sub": agent_id, "aud": issuer, "client_id": agent_id, "client_type": "agent",
        "client_name": agent_name, "sponsor": sponsor, "scope": scope,
        "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8),
    }


def mint_delegated_token(key: SigningKey, claims: dict) -> dict:
    token = jwt.encode(claims, key.private_pem, algorithm="RS256", headers={"kid": key.kid})
    return {
        "access_token": token, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer", "expires_in": claims["exp"] - claims["iat"], "scope": claims["scope"],
    }


def mint_service_token(key: SigningKey, *, issuer: str, client_id: str, scope: str) -> dict:
    """An access token for a service acting as itself. There is no user, so
    `sub` is the client's own id, which is also how a resource server tells it
    apart from a token issued on a human's behalf."""
    now = int(time.time())
    client = SERVICE_CLIENTS[client_id]
    ttl = AGENT_TOKEN_TTL_SECONDS if client["client_type"] == "agent" else SERVICE_TOKEN_TTL_SECONDS
    claims = {
        "iss": issuer,
        "sub": client_id,
        "aud": issuer,
        "client_id": client_id,
        "client_type": client["client_type"],
        "client_name": client["name"],
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),
    }
    if client.get("sponsor"):
        claims["sponsor"] = client["sponsor"]
    if client.get("capabilities"):
        claims["capabilities"] = capabilities_for_scopes(client["capabilities"], set(scope.split()))
    token = jwt.encode(claims, key.private_pem, algorithm="RS256", headers={"kid": key.kid})
    return {"access_token": token, "token_type": "Bearer", "expires_in": ttl, "scope": scope}


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
        "client_type": claims.get("client_type"),
        "client_name": claims.get("client_name"),
        "sponsor": claims.get("sponsor"),
        "capabilities": claims.get("capabilities"),
        "acting_as": claims.get("acting_as"),
        "iss": claims["iss"],
        "exp": claims["exp"],
        "iat": claims["iat"],
        "jti": claims["jti"],
        "token_type": "Bearer",
    }
