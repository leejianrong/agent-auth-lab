"""Acting for a person: claim a task, trade the person's token for a delegated
one, and hand the runner a token to use against downstream APIs.

The agent's own token and the delegated one are different things and are kept
apart. The runner uses the delegated token only for tools marked `delegated`,
and the agent's own for everything else.
"""

from dataclasses import dataclass

import httpx

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


@dataclass
class Delegation:
    token: str
    scope: str
    task_id: int
    trace_id: str


def claim_task(http: httpx.Client, api_url: str, agent_token: str, kind: str | None = None) -> dict | None:
    """Ask the app for the next pending task (of one kind, if given), or None if
    there isn't one."""
    res = http.get(
        f"{api_url}/agent/tasks/next", params={"kind": kind} if kind else None,
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    res.raise_for_status()
    return res.json()["task"]


def exchange(
    http: httpx.Client, idp_url: str, client_id: str, secret: str, task: dict, scope: str,
) -> Delegation:
    """RFC 8693: present our own credentials and the person's token, get back
    a token that names the person and us."""
    res = http.post(
        f"{idp_url}/token",
        data={"grant_type": TOKEN_EXCHANGE, "subject_token": task["subject_token"], "scope": scope},
        auth=(client_id, secret),
        headers={"X-Trace-Id": task["trace_id"]},
    )
    if res.status_code != 200:
        raise PermissionError(f"IdP refused the delegation ({res.status_code}: {res.json().get('error', '?')})")
    body = res.json()
    return Delegation(body["access_token"], body["scope"], task["id"], task["trace_id"])


def complete_task(http: httpx.Client, api_url: str, agent_token: str, task_id: int) -> None:
    http.post(f"{api_url}/agent/tasks/{task_id}/complete", headers={"Authorization": f"Bearer {agent_token}"}).raise_for_status()


def hand_off(
    http: httpx.Client, idp_url: str, api_url: str, client_id: str, secret: str, agent_token: str,
    delegation: Delegation, target: str, scope: str,
) -> int:
    """Pass part of the work, and so part of the person's authority, to another
    agent. The IdP makes a token for `target` with only `scope` in it (the part
    we are explicitly re-granting), and we leave it where the target will look.
    Returns the hand-off's id."""
    res = http.post(
        f"{idp_url}/token",
        data={"grant_type": TOKEN_EXCHANGE, "subject_token": delegation.token, "scope": scope, "audience": target},
        auth=(client_id, secret),
        headers={"X-Trace-Id": delegation.trace_id},
    )
    if res.status_code != 200:
        raise PermissionError(f"IdP refused the hand-off to {target} ({res.status_code}: {res.json().get('error', '?')})")
    hop_token = res.json()["access_token"]
    res = http.post(
        f"{api_url}/agent/handoffs", json={"target": target, "token": hop_token},
        headers={"Authorization": f"Bearer {agent_token}", "X-Trace-Id": delegation.trace_id},
    )
    res.raise_for_status()
    return res.json()["id"]


def claim_handoff(http: httpx.Client, api_url: str, agent_token: str) -> dict | None:
    """Ask the app for work another agent has handed to us, or None."""
    res = http.get(f"{api_url}/agent/handoffs/next", headers={"Authorization": f"Bearer {agent_token}"})
    res.raise_for_status()
    return res.json()["handoff"]


def complete_handoff(http: httpx.Client, api_url: str, agent_token: str, handoff_id: int) -> None:
    http.post(f"{api_url}/agent/handoffs/{handoff_id}/complete", headers={"Authorization": f"Bearer {agent_token}"}).raise_for_status()
