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
#
# Lab 10: a capability can also say `"approval": "required"`. The token carries
# it like any other limit, and the policy turns it into "a person has to say
# yes first".
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
        "allowed_scopes": {"stats:read", "reports:write", "reports:purge"},
        "capabilities": [
            {"tool": "get_stats", "scope": "stats:read"},
            {"tool": "write_report", "scope": "reports:write", "max_body_chars": 200},
            {"tool": "purge_reports", "scope": "reports:purge", "approval": "required"},
        ],
        # Lab 09: the most this agent can ever do on behalf of a person, however
        # much that person has agreed to. Delegation can only narrow, so the
        # scopes on a delegated token are the overlap of three lists.
        "delegable_scopes": {"notes:read", "notes:write"},
        # Lab 11: the agents this one may pass its work, and so part of a
        # person's authority, on to.
        "hand_off_to": {"archive-agent"},
    },
    # Lab 11: a second agent, run by a different sponsor. It files copies of a
    # person's notes, so the most it is ever trusted with is reading them.
    "archive-agent": {
        "name": "Archive agent",
        "client_type": "agent",
        "sponsor": "idp-bob",
        "secret_sha256": hashlib.sha256(b"archive-agent-secret-do-not-reuse").hexdigest(),
        "allowed_scopes": {"reports:write"},
        "capabilities": [
            {"tool": "write_report", "scope": "reports:write", "max_body_chars": 200},
        ],
        "delegable_scopes": {"notes:read"},
    },
}
MAX_HAND_OFFS = 1   # a person's authority passes through at most one extra agent
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
    "reports:purge": "Delete old reports (agents only, a person must approve each time)",
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
    return requested & subject_scope & delegable


def compose_delegated_claims(
    subject: dict, *, agent_id: str, agent_name: str, sponsor: str | None, scope: str,
    issuer: str, now: int, ttl: int,
) -> dict:
    """The claims of a token an agent holds while acting for a person (the
    idea of RFC 8693 token exchange). `subject` is the introspected token of
    the person, as returned by `introspect_token`.

    The token has to say two things at once, and downstream services need both:
    whose authority this is, and who is exercising it."""
    claims = {
        "iss": issuer,
        "sub": subject["sub"],
        "aud": issuer,
        "client_id": agent_id,
        "client_type": "agent",
        "client_name": agent_name,
        "sponsor": sponsor,
        "scope": scope,
        "acting_as": {"sub": agent_id, "sponsor": sponsor},
        "iat": now,
        "exp": min(now + ttl, subject["exp"]),
        "jti": secrets.token_hex(8),
    }
    return claims


def narrow_hop_scope(held: set[str], regranted: set[str], ceiling: set[str]) -> set[str]:
    """Which scopes may the token for the next agent in a chain carry? The
    agent passing the work on holds `held`. It names, explicitly, the part it is
    re-granting (`regranted`). The receiving agent is registered for at most
    `ceiling`. Nothing is inherited: a hop gets only what was handed to it on
    purpose, and never more than either side could use alone."""
    return held & regranted & ceiling


def compose_hop_claims(
    subject: dict, *, target_id: str, target_name: str, target_sponsor: str | None, scope: str,
    issuer: str, now: int, ttl: int,
) -> dict:
    """The claims of the token the next agent in a chain holds. `subject` is the
    introspected token of the agent handing the work on, which is itself a
    delegated token with `acting_as`.

    The new token has to stay Alice's authority, say who is exercising it now,
    and remember who it came through, so that whatever the second agent does
    can be traced back along the chain and never lands on the first agent."""
    via = [*subject["acting_as"].get("via", []), subject["acting_as"]["sub"]]
    claims = {
        "iss": issuer,
        "sub": subject["sub"],
        "aud": issuer,
        "client_id": target_id,
        "client_type": "agent",
        "client_name": target_name,
        "sponsor": target_sponsor,
        "scope": scope,
        "acting_as": {"sub": target_id, "sponsor": target_sponsor, "via": via},
        "iat": now,
        "exp": min(now + ttl, subject["exp"]),
        "jti": secrets.token_hex(8),
    }
    return claims


def may_redelegate(subject: dict, presenter_id: str, target_id: str, registry: dict) -> tuple[bool, str]:
    """May `presenter_id` pass the delegated token `subject` on to `target_id`?
    Returns `(allowed, reason)`. `registry` is `SERVICE_CLIENTS`: each agent's
    `hand_off_to` says who it may pass work to."""
    if not subject.get("active"):
        return False, "the token is not active (expired, revoked or invalid)"
    acting = subject.get("acting_as")
    if not acting:
        return False, "the token is not delegated, so there is nothing to pass on"
    if presenter_id != acting.get("sub"):
        return False, f"only {acting.get('sub')}, the agent this token was issued to, may pass it on"
    if target_id not in registry.get(presenter_id, {}).get("hand_off_to", set()):
        return False, f"{presenter_id} is not registered to hand work to {target_id or 'that agent'}"
    if target_id == presenter_id or target_id in acting.get("via", []):
        return False, "work cannot be handed back along the chain"
    if len(acting.get("via", [])) >= MAX_HAND_OFFS:
        return False, f"a person's authority may pass through at most {MAX_HAND_OFFS} extra agent"
    return True, "hand-off allowed"


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


def revoked_clients(conn: sqlite3.Connection) -> set[str]:
    """Every client that has been cut off, read from the database each time it is
    asked. Nothing here is cached, so a cut-off bites on the next request."""
    return {r["client_id"] for r in conn.execute("SELECT client_id FROM revoked_clients").fetchall()}


def cut_off_client(conn: sqlite3.Connection, client_id: str, by: str, reason: str | None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO revoked_clients (client_id, revoked_at, revoked_by, reason) VALUES (?, ?, ?, ?)",
        (client_id, time.time(), by, reason),
    )
    conn.commit()


def restore_client(conn: sqlite3.Connection, client_id: str) -> None:
    conn.execute("DELETE FROM revoked_clients WHERE client_id = ?", (client_id,))
    conn.commit()


def token_cut_off(claims: dict, cut_off: set[str]) -> str | None:
    """Has this token been cut off because of who it belongs to, or who it came
    through? Returns the reason, or None when it is fine. `claims` is the decoded
    token, `cut_off` the set of client ids that have been revoked.

    A token is only as trustworthy as every agent in its history. A delegated
    token made for the archive agent by the tidy agent carries `acting_as.via`,
    and cutting the tidy agent off has to cut off what it handed on."""
    # LAB:SOLUTION >>>
    if claims.get("client_id") in cut_off:
        return f"{claims['client_id']} has been cut off"
    acting = claims.get("acting_as") or {}
    if acting.get("sub") in cut_off:
        return f"{acting['sub']} has been cut off"
    for upstream in acting.get("via", []):
        if upstream in cut_off:
            return f"{upstream}, an agent this authority passed through, has been cut off"
    return None
    # LAB:SOLUTION <<<
    # LAB:STARTER >>>
    # TODO(lab-12): this only looks at the client the token was issued to. A
    # token made for the archive agent by the tidy agent still works after the
    # tidy agent is cut off, so the kill-switch leaks through the chain. Return a
    # reason (a short sentence naming the agent) when any of three things is in
    # `cut_off`: the token's `client_id`; the agent in `acting_as["sub"]`; or any
    # agent in `acting_as["via"]`. Return None when none is.
    if claims.get("client_id") in cut_off:
        return f"{claims['client_id']} has been cut off"
    return None
    # LAB:STARTER <<<


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
    if token_cut_off(claims, revoked_clients(conn)):
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
