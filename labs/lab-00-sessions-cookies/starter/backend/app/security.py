import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

SESSION_TTL_SECONDS = 60 * 30  # 30 minutes


def hash_password(password: str) -> str:
    # TODO(lab-00): this stores the password as-is. Anyone who reads the
    # database (a backup, a leaked file, an SQL-injection bug elsewhere)
    # gets every user's real password. Hash it instead — see the "Password
    # Hashing" section of the lab 00 handout, and the `argon2` package
    # that's already a dependency.
    return password


def verify_password(password: str, password_hash: str) -> bool:
    # TODO(lab-00): this only works because hash_password() above doesn't
    # actually hash anything yet. Once you fix hash_password(), this needs
    # to verify against the hash, not compare raw strings.
    return password == password_hash


def new_session_id() -> str:
    """High-entropy opaque token — not a guessable sequence, not the user ID."""
    return secrets.token_urlsafe(32)


def resolve_login_session_id(cookie_session_id: str | None) -> str:
    """What session id does a successful login issue?"""
    # TODO(lab-00): reusing whatever session id the client already sent (or
    # minting one only if none was sent) opens session fixation — an
    # attacker can set a victim's cookie *before* they log in, then reuse
    # that same session id afterward, now authenticated as the victim.
    # Always issue a fresh session id here instead. See "Session Fixation"
    # in the lab 00 handout.
    return cookie_session_id or new_session_id()


def session_expiry(now: float | None = None) -> float:
    return (now or time.time()) + SESSION_TTL_SECONDS
