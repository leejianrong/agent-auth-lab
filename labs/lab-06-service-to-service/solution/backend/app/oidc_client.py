"""The capstone app's side of "Sign in with Lab IdP": an OpenID Connect
relying party using the authorization code flow with PKCE.

It never sees the user's password. It sends the browser to the IdP, gets a
single-use code back, and trades that code (plus a secret only it knows) for
signed tokens over a direct server-to-server call.
"""

import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK

from observability_harness import current_trace_id

# Where this app's server reaches the IdP, and where the user's browser does.
# They are the same on one machine and different under docker-compose (the
# app calls http://idp:9000, the browser opens http://localhost:9000). The
# tokens' `iss` is the browser-facing one, so that's what we validate against.
IDP_URL = os.environ.get("LAB_IDP_URL", "http://localhost:9000")
PUBLIC_IDP_URL = os.environ.get("LAB_IDP_PUBLIC_URL", IDP_URL)
ISSUER = PUBLIC_IDP_URL
CLIENT_ID = "lab-client"
REDIRECT_URI = os.environ.get("LAB_OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback")
FRONTEND_URL = os.environ.get("LAB_FRONTEND_URL", "http://localhost:5173")

# Lab 05: what this app asks the user for, and who it is when it asks the IdP
# whether an access token is still good (ADR-0008: fixed, localhost-only).
SCOPE = "openid profile notes:read notes:write"
RESOURCE_SERVER_ID = "lab-resource-server"
RESOURCE_SERVER_SECRET = "lab-resource-server-secret-do-not-reuse"

_http = httpx.Client(timeout=5.0)
_jwks_cache: dict[str, dict] = {}


def set_http_client(client: httpx.Client) -> None:
    """Tests point this at an in-process copy of the IdP."""
    global _http
    _http = client
    _jwks_cache.clear()


class OidcError(Exception):
    """A login failure with a human-readable `reason` for the audit log."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def make_pkce_pair() -> tuple[str, str]:
    """Return `(code_verifier, code_challenge)` for one login attempt.

    The verifier is a high-entropy secret the app keeps. The challenge is
    what it sends to the IdP up front: the SHA-256 hash of the verifier,
    base64url-encoded without padding (the S256 method from RFC 7636).
    """
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def new_state() -> str:
    return secrets.token_urlsafe(24)


def new_nonce() -> str:
    return secrets.token_urlsafe(24)


def build_authorize_url(*, state: str, nonce: str, code_challenge: str, trace_id: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "trace_id": trace_id,  # lab-only: lets the trace viewer join both services
    }
    return f"{PUBLIC_IDP_URL}/authorize?{urlencode(params)}"


def exchange_code(code: str, code_verifier: str) -> dict:
    """Back-channel call to the token endpoint. Raises OidcError on failure."""
    try:
        res = _http.post(
            f"{IDP_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier,
            },
            headers={"X-Trace-Id": current_trace_id() or ""},
        )
    except httpx.HTTPError as e:
        raise OidcError(f"could not reach the IdP token endpoint ({type(e).__name__})") from e
    if res.status_code != 200:
        error = res.json().get("error", "unknown") if res.headers.get("content-type", "").startswith("application/json") else "unknown"
        raise OidcError(f"token endpoint refused the code exchange: {error}")
    return res.json()


def _signing_key_for(kid: str | None):
    """Find the IdP's public key for `kid`, refetching the JWKS once when it
    isn't cached (the IdP may have rotated its key)."""
    if kid is None:
        raise OidcError("ID token header has no kid")
    for attempt in (0, 1):
        if kid in _jwks_cache:
            return PyJWK(_jwks_cache[kid]).key
        if attempt == 0:
            try:
                res = _http.get(f"{IDP_URL}/jwks.json")
                res.raise_for_status()
            except httpx.HTTPError as e:
                raise OidcError(f"could not fetch the IdP's JWKS ({type(e).__name__})") from e
            for jwk in res.json().get("keys", []):
                _jwks_cache[jwk["kid"]] = jwk
    raise OidcError("ID token is signed with a key the IdP does not publish")


def validate_id_token(id_token: str, *, expected_nonce: str) -> dict:
    """Check an ID token before believing anything in it, and return its
    claims. Raise `OidcError` (with a specific reason) if it fails any check.

    An ID token is only evidence of who logged in if: the IdP's key really
    signed it, it was issued by the IdP we expect, it was issued for *this*
    app, it hasn't expired, and it answers *this* login attempt (the nonce).
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as e:
        raise OidcError("ID token is not well-formed") from e
    if header.get("alg") != "RS256":
        raise OidcError(f"unexpected signing algorithm {header.get('alg')!r}, expected RS256")
    key = _signing_key_for(header.get("kid"))
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise OidcError("ID token expired") from e
    except jwt.InvalidAudienceError as e:
        raise OidcError("ID token audience is not this client") from e
    except jwt.InvalidIssuerError as e:
        raise OidcError("ID token issuer is not the Lab IdP") from e
    except jwt.InvalidSignatureError as e:
        raise OidcError("ID token signature is invalid") from e
    except jwt.InvalidTokenError as e:
        raise OidcError(f"ID token rejected: {e}") from e
    if not secrets.compare_digest(str(claims.get("nonce", "")), expected_nonce):
        raise OidcError("ID token nonce does not match this login attempt")
    return claims


def introspect(access_token: str) -> dict:
    """Ask the IdP whether an access token is still good and what it grants
    (RFC 7662). Called on every request from a signed-in federated user, so
    a revocation takes effect on their very next action.

    If the IdP can't be reached this reports the token as inactive: failing
    closed means an outage locks people out, failing open means a revoked
    token keeps working. For access control we pick the first."""
    try:
        res = _http.post(
            f"{IDP_URL}/introspect",
            data={"token": access_token},
            auth=(RESOURCE_SERVER_ID, RESOURCE_SERVER_SECRET),
            headers={"X-Trace-Id": current_trace_id() or ""},
        )
        if res.status_code != 200:
            return {"active": False}
        return res.json()
    except httpx.HTTPError:
        return {"active": False}


def revoke(access_token: str) -> None:
    """Tell the IdP to stop honouring this token (RFC 7009)."""
    try:
        _http.post(f"{IDP_URL}/revoke", data={"token": access_token, "client_id": CLIENT_ID})
    except httpx.HTTPError as e:
        raise OidcError(f"could not reach the IdP revocation endpoint ({type(e).__name__})") from e


def has_scope(granted: str, required: str) -> bool:
    """Does the space-delimited `granted` string include the scope `required`?"""
    return required in granted.split()


def service_token_allowed(result: dict, required_scope: str) -> tuple[bool, str]:
    """Should a request carrying this introspected token be let in to a
    service-only endpoint? Returns `(allowed, reason)`; the reason goes to
    the audit log either way.

    Service tokens and user tokens come from the same IdP and look alike, so
    "the IdP says it's active" isn't enough: the endpoint also has to confirm
    the token was issued to a service acting as itself (a human's token has a
    `sub` that is a user, a service's has `sub` equal to its own client id)
    and that it holds the scope this endpoint needs.
    """
    # LAB:SOLUTION >>>
    if not result.get("active"):
        return False, "token is not active (expired, revoked or invalid)"
    if result.get("sub") != result.get("client_id"):
        return False, "token was issued on behalf of a user, not to a service"
    if not has_scope(result.get("scope", ""), required_scope):
        return False, f"insufficient_scope: needs '{required_scope}', token grants '{result.get('scope', '')}'"
    return True, "service token accepted"
    # LAB:SOLUTION <<<
    # LAB:STARTER >>>
    # TODO(lab-06): this lets in any active token, whoever it was issued to
    # and whatever it grants. That means a human's access token, or a
    # service token for some other job, opens an endpoint it was never meant
    # for. Check three things, in this order, and return a specific reason
    # for each failure: the token is active; it was issued to a service
    # (`sub` equal to `client_id`, not a user); it holds `required_scope`
    # (use `has_scope`).
    return bool(result.get("active")), "token is active"
    # LAB:STARTER <<<
