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
    try:
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return TokenVerification(
            valid=False, signature_valid=False, expired=False,
            reason="token is not well-formed",
        )

    now = time.time()
    claimed_exp = unverified_claims.get("exp")
    exp_present = "exp" in unverified_claims
    exp_well_formed = isinstance(claimed_exp, (int, float))
    expired = exp_well_formed and claimed_exp < now

    try:
        # verify_exp is turned off deliberately: this call's only job is
        # checking the signature. PyJWT's own exp handling (left on) would
        # try to int() a malformed exp claim and raise DecodeError — a
        # subclass of InvalidTokenError indistinguishable, in the except
        # branch below, from an actually-forged signature. A malformed exp
        # is a real, distinct problem (handled right below), but it isn't a
        # signature problem, and this function must not conflate the two.
        jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        signature_valid = True
    except jwt.InvalidTokenError:
        signature_valid = False

    if not signature_valid:
        return TokenVerification(
            valid=False, signature_valid=False, expired=expired,
            claims=unverified_claims, reason="invalid signature",
        )

    if exp_present and not exp_well_formed:
        return TokenVerification(
            valid=False, signature_valid=True, expired=False,
            claims=unverified_claims, reason="malformed exp claim",
        )

    if expired:
        return TokenVerification(
            valid=False, signature_valid=True, expired=True,
            claims=unverified_claims, reason="token expired",
        )

    missing = [claim for claim in REQUIRED_CLAIMS if claim not in unverified_claims]
    if missing:
        return TokenVerification(
            valid=False, signature_valid=True, expired=False,
            claims=unverified_claims, reason=f"missing required claim: {missing[0]}",
        )

    return TokenVerification(valid=True, signature_valid=True, expired=False, claims=unverified_claims)


ADMIN_ROLE = "admin"
USER_ROLE = "user"


def role_is_authorized(role: str, allowed_roles: tuple[str, ...]) -> bool:
    """Does `role` satisfy the RBAC check for a route that only admits one
    of `allowed_roles`?

    Kept as a standalone, dependency-free predicate — same reason
    `verify_token` above is a plain function rather than living inline in a
    FastAPI route — so it can be unit-tested directly, without spinning up
    the app or a session.
    """
    return role in allowed_roles
