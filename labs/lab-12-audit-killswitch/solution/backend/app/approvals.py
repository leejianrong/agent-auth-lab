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
import sqlite3

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


def cut_off_pending_work(conn: sqlite3.Connection, agent_id: str, now: float) -> int:
    """Lab 12: an agent has been cut off. Whatever it had waiting has to die with
    it, or a person could still approve a request from an agent that no longer
    exists, and a token minted for it would sit in a table. End every approval
    request of this agent that is still pending or approved (the state machine's
    `expire` event gives the final state, and the token is wiped), cancel hand-
    offs it gave or was given that are not finished (wipe their tokens), and
    cancel tasks it claimed but did not complete (wipe the person's token).
    Returns how many rows were ended, across all three tables."""
    # LAB:SOLUTION >>>
    ended = 0
    for row in conn.execute(
        "SELECT id, status FROM approvals WHERE agent_id = ? AND status IN (?, ?)", (agent_id, PENDING, APPROVED)
    ).fetchall():
        conn.execute(
            "UPDATE approvals SET status = ?, approval_token = NULL, decided_by = 'kill-switch', decided_at = ?, "
            "decision_note = 'the agent was cut off' WHERE id = ?",
            (transition(row["status"], "expire"), now, row["id"]),
        )
        ended += 1
    ended += conn.execute(
        "UPDATE agent_handoffs SET status = 'cancelled', token = NULL "
        "WHERE (from_agent = ? OR to_agent = ?) AND status IN ('pending', 'claimed')", (agent_id, agent_id),
    ).rowcount
    ended += conn.execute(
        "UPDATE agent_tasks SET status = 'cancelled', subject_token = NULL WHERE claimed_by = ? AND status = 'claimed'",
        (agent_id,),
    ).rowcount
    conn.commit()
    return ended
    # LAB:SOLUTION <<<
    # LAB:STARTER >>>
    # TODO(lab-12): this leaves everything the agent had in flight exactly as it
    # was. Do three updates and return the number of rows they changed in total.
    # Approval requests of this agent that are `pending` or `approved`: set the
    # status to what `transition(status, "expire")` gives, null `approval_token`,
    # and note who ended it (`decided_by = 'kill-switch'`). Rows in
    # `agent_handoffs` where it is `from_agent` or `to_agent` and the status is
    # `pending` or `claimed`: status `cancelled`, `token` null. Rows in
    # `agent_tasks` it `claimed_by` and not finished: status `cancelled`,
    # `subject_token` null. Commit when you are done.
    return 0
    # LAB:STARTER <<<
