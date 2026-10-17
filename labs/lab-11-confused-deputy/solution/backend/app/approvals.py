"""The approval gate's rules, kept apart from the web layer so each one can be
tested on its own.

An elevated tool call does not run when the agent asks. It becomes a request
that waits for a person. The request moves through a small set of states:

    pending ──approve──▶ approved ──use──▶ used
       │                    │
       ├──deny──▶ denied    └──expire──▶ expired
       └──expire──▶ expired

An approval is a short-lived token the agent presents when it repeats the call.
It is good for one call, by one agent, to one tool, with the arguments that were
approved, for a minute.
"""

import hashlib
import json
import secrets

PENDING, APPROVED, DENIED, EXPIRED, USED = "pending", "approved", "denied", "expired", "used"

REQUEST_TTL_SECONDS = 300   # a request nobody answers dies after five minutes
TOKEN_TTL_SECONDS = 60      # an approval token is good for one minute


class InvalidTransition(Exception):
    """The request is in a state that doesn't allow this event."""


def transition(status: str, event: str) -> str:
    """The state a request moves to when `event` ("approve", "deny", "use" or
    "expire") happens to a request that is in `status`. Raises
    `InvalidTransition` when that is not allowed: a decision, once made, is
    final."""
    allowed = {
        PENDING: {"approve": APPROVED, "deny": DENIED, "expire": EXPIRED},
        APPROVED: {"use": USED, "expire": EXPIRED},
    }.get(status, {})
    if event not in allowed:
        raise InvalidTransition(f"a {status} request cannot be moved by '{event}'")
    return allowed[event]


def args_digest(tool: str, args: dict) -> str:
    """A fingerprint of exactly what is being asked for. The approval is tied to
    this, so approving one call can't be spent on a different one."""
    canonical = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(24)


def may_decide(*, role: str, idp_sub: str | None, sponsor: str | None) -> tuple[bool, str]:
    """May this signed-in person approve or deny a request from an agent whose
    sponsor is `sponsor`? Returns `(allowed, reason)`; the reason is audited."""
    if role == "admin":
        return True, "an admin may decide any request"
    if sponsor and idp_sub == sponsor:
        return True, "the agent's sponsor may decide its requests"
    return False, "only an admin or the agent's sponsor may decide this request"


def approval_token_allowed(
    row, presented: str, *, agent_id: str, tool: str, digest: str, now: float,
) -> tuple[bool, str]:
    """Should this call go ahead on the strength of the approval `row` and the
    token `presented` with it? Returns `(allowed, reason)`.

    `row` has the stored `status`, `approval_token`, `token_expires_at`,
    `agent_id`, `tool` and `args_digest`. A token that is real is not enough:
    it has to be live, and it has to belong to this exact call."""
    if row["status"] != APPROVED:
        return False, f"the approval is {row['status']}, not approved"
    if not row["approval_token"] or not secrets.compare_digest(row["approval_token"], presented or ""):
        return False, "the approval token does not match"
    if now >= row["token_expires_at"]:
        return False, "the approval token has expired"
    if agent_id != row["agent_id"]:
        return False, "the approval was granted to a different agent"
    if tool != row["tool"]:
        return False, "the approval was granted for a different tool"
    if digest != row["args_digest"]:
        return False, "the approval was granted for different arguments"
    return True, "approval accepted"


def is_due(row, now: float) -> bool:
    """Has this request run out of time? A pending one runs out at `expires_at`,
    an approved one when its token does."""
    if row["status"] == PENDING:
        return now >= row["expires_at"]
    if row["status"] == APPROVED:
        return row["token_expires_at"] is not None and now >= row["token_expires_at"]
    return False
