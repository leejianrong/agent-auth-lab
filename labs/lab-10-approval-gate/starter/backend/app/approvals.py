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
    # TODO(lab-10): this moves any request anywhere, so a denied request can be
    # approved later and a used one can be used again. The states are pending,
    # approved, denied, expired and used. From pending, `approve`, `deny` and
    # `expire` are allowed. From approved, `use` and `expire` are. Denied,
    # expired and used are final: every event raises `InvalidTransition`. So does
    # an event that doesn't belong to the state it arrives in.
    return {"approve": APPROVED, "deny": DENIED, "use": USED, "expire": EXPIRED}[event]


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
    # TODO(lab-10): this lets any signed-in person decide any request, so an
    # ordinary user could approve an agent's purge for someone else. Allow the
    # decision only for an admin (`role == "admin"`) or for the agent's sponsor
    # (`idp_sub` equal to `sponsor`, and `sponsor` actually set). Give each
    # answer its own reason.
    return True, "any signed-in person may decide"


def approval_token_allowed(
    row, presented: str, *, agent_id: str, tool: str, digest: str, now: float,
) -> tuple[bool, str]:
    """Should this call go ahead on the strength of the approval `row` and the
    token `presented` with it? Returns `(allowed, reason)`.

    `row` has the stored `status`, `approval_token`, `token_expires_at`,
    `agent_id`, `tool` and `args_digest`. A token that is real is not enough:
    it has to be live, and it has to belong to this exact call."""
    # TODO(lab-10): this accepts any request that holds the right token string.
    # An approval for one agent, one tool and one set of arguments could be spent
    # by another agent, on another tool, with other arguments, long after. Check,
    # in order, each with its own reason: the request's `status` is approved; the
    # token matches (`secrets.compare_digest`, and a request with no stored token
    # never matches); `now` is before `token_expires_at`; `agent_id` is the
    # agent the request was made by; `tool` is the tool it asked for; and
    # `digest` equals the stored `args_digest`.
    return bool(row["approval_token"]) and secrets.compare_digest(row["approval_token"], presented or ""), "token matches"


def is_due(row, now: float) -> bool:
    """Has this request run out of time? A pending one runs out at `expires_at`,
    an approved one when its token does."""
    if row["status"] == PENDING:
        return now >= row["expires_at"]
    if row["status"] == APPROVED:
        return row["token_expires_at"] is not None and now >= row["token_expires_at"]
    return False
