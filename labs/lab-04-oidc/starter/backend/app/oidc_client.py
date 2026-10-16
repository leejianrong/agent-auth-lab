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

IDP_URL = os.environ.get("LAB_IDP_URL", "http://localhost:9000")
ISSUER = IDP_URL
CLIENT_ID = "lab-client"
REDIRECT_URI = os.environ.get("LAB_OIDC_REDIRECT_URI", "http://localhost:8000/auth/oidc/callback")
FRONTEND_URL = os.environ.get("LAB_FRONTEND_URL", "http://localhost:5173")

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
    # TODO(lab-04): this sends the verifier itself as the challenge (the
    # "plain" method). Anyone who sees the authorize redirect then holds the
    # secret too, which defeats the point of PKCE, and the IdP only accepts
    # S256. Derive the challenge by hashing the verifier with SHA-256 and
    # encoding the digest as base64url with the "=" padding stripped.
    verifier = secrets.token_urlsafe(48)
    return verifier, verifier


def new_state() -> str:
    return secrets.token_urlsafe(24)


def new_nonce() -> str:
    return secrets.token_urlsafe(24)


def build_authorize_url(*, state: str, nonce: str, code_challenge: str, trace_id: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "trace_id": trace_id,  # lab-only: lets the trace viewer join both services
    }
    return f"{IDP_URL}/authorize?{urlencode(params)}"


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
    # TODO(lab-04): this reads the claims without checking anything, so a
    # forged or replayed token logs the attacker in. Before trusting the
    # claims you need to:
    #   1. read the header and refuse any `alg` other than RS256
    #   2. get the IdP's public key for the header's `kid` (`_signing_key_for`)
    #   3. verify the signature, `iss`, `aud` and `exp` in one `jwt.decode`
    #   4. compare the `nonce` claim to `expected_nonce`
    # Raise `OidcError("...")` with a specific reason for each failure; the
    # self-check tests look at which check fired.
    return jwt.decode(id_token, options={"verify_signature": False})
