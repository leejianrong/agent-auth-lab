import secrets
import time
from dataclasses import dataclass

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

SESSION_TTL_SECONDS = 60 * 30  # 30 minutes

# ADR-0008: this is a fixed, checked-in secret so the lab runs with zero
# setup. Never do this outside a localhost teaching exercise — a real
# deployment loads this from an environment variable / secrets manager, not
# from source control.
JWT_SECRET = "lab01-teaching-secret-do-not-reuse"
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 60 * 15  # 15 minutes — short-lived on purpose

REQUIRED_CLAIMS = ("sub", "exp")


@dataclass
class TokenVerification:
    """Result of checking a JWT. `signature_valid` and `expired` are reported
    separately from the overall `valid` flag because the UI needs to show
    them separately: the client can already read `claims` (and therefore
    guess whether the token *looks* expired) without ever talking to the
    server, but it has no way to know whether the signature is genuine
    until the server checks it with the key that issued it."""

    valid: bool
    signature_valid: bool
    expired: bool
    claims: dict | None = None
    reason: str | None = None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


def new_session_id() -> str:
    """High-entropy opaque token — not a guessable sequence, not the user ID."""
    return secrets.token_urlsafe(32)


def resolve_login_session_id(cookie_session_id: str | None) -> str:
    """What session id does a successful login issue?"""
    return new_session_id()


def session_expiry(now: float | None = None) -> float:
    return (now or time.time()) + SESSION_TTL_SECONDS


def issue_token(username: str) -> str:
    """Mint a JWT for an already-authenticated session. Stateless and
    self-contained: unlike the session table above, nothing about this
    token is stored anywhere — the signature is the only thing that will
    ever prove it came from us."""
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + JWT_TTL_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> TokenVerification:
    """Check a JWT for real: signature, expiry, and required claims.

    Decoding the payload is always possible without the secret — that part
    of a JWT is base64url, not encrypted. Proving the token wasn't tampered
    with, and hasn't expired, needs the actual signature check below.
    """
    # TODO(lab-01): this reads the claims out of the token but never checks
    # whether the signature is genuine — jwt.decode() below is called with
    # verify_signature=False, so it happily accepts a token whose payload
    # was hand-edited and re-encoded, as long as the JSON is well-formed. A
    # JWT's payload is base64url, not encrypted: readable by anyone, proven
    # authentic by no one, until the signature is actually checked against
    # the key that issued it. Verify the signature for real instead of
    # skipping it — decode with the secret and `algorithms=[JWT_ALGORITHM]`,
    # no `verify_signature` override — and handle the distinct failure
    # cases (bad signature, expired, missing claim) it can raise. See
    # "Signed, Not Encrypted" in the lab 01 handout.
    claims = jwt.decode(token, options={"verify_signature": False})

    now = time.time()
    claimed_exp = claims.get("exp")
    expired = isinstance(claimed_exp, (int, float)) and claimed_exp < now
    if expired:
        return TokenVerification(
            valid=False, signature_valid=True, expired=True, claims=claims,
            reason="token expired",
        )

    missing = [claim for claim in REQUIRED_CLAIMS if claim not in claims]
    if missing:
        return TokenVerification(
            valid=False, signature_valid=True, expired=False, claims=claims,
            reason=f"missing required claim: {missing[0]}",
        )

    return TokenVerification(valid=True, signature_valid=True, expired=False, claims=claims)
