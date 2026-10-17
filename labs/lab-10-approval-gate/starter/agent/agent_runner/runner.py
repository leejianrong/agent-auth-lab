"""Runs an agent: offers it tools, executes what it asks for with the
agent's own token, and records what happened."""

import secrets
import time
from collections.abc import Callable

import httpx

from .agent import Action, Agent, Observation
from .approval import ApprovalWait, wait_for_decision
from .auth import TokenManager
from .delegation import Delegation, claim_task, complete_task, exchange
from .tools import TOOLS, Tool, tools_for_scopes


def execute(
    tool: Tool, action: Action, token: str, api_http: httpx.Client, api_url: str, trace_id: str,
    *, approval: dict | None = None, wait: ApprovalWait | None = None, token_for=None,
) -> Observation:
    """Make one tool call. If the gateway holds it for a person's approval, wait
    for the decision (when the runner was set up to) and repeat the call with the
    approval token that comes back."""
    headers = {"Authorization": f"Bearer {token}", "X-Trace-Id": trace_id}
    if tool.delegated:
        res = api_http.request(tool.method, f"{api_url}{tool.path}", headers=headers)
    else:
        body = {"args": {k: str(action.args.get(k, "")) for k in tool.params}, **(approval or {})}
        res = api_http.request(tool.method, f"{api_url}{tool.path}", headers=headers, json=body)
    try:
        payload = res.json()
    except ValueError:
        payload = None
    if res.status_code == 202 and isinstance(payload, dict) and payload.get("status") == "pending_approval":
        if wait is None or approval is not None:
            return Observation(action, False, error=f"needs a person's approval (request {payload['approval_id']}), and this runner is not waiting")
        outcome = wait_for_decision(
            api_http, api_url, token_for or (lambda: token), payload["approval_id"], tool.name, trace_id, wait,
        )
        if outcome["status"] != "approved":
            note = f" ({outcome['note']})" if outcome.get("note") else ""
            return Observation(action, False, error=f"approval {outcome['status']}{note}")
        return execute(
            tool, action, token_for() if token_for else token, api_http, api_url, trace_id,
            approval={"approval_id": payload["approval_id"], "approval_token": outcome["approval_token"]}, wait=wait,
            token_for=token_for,
        )
    if res.status_code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) else res.text
        return Observation(action, False, error=f"{res.status_code}: {detail}")
    return Observation(action, True, result=payload)


def run_once(
    agent: Agent, tokens: TokenManager, api_http: httpx.Client, api_url: str,
    *, trace_id: str | None = None, max_actions: int = 10, enforce_offer: bool = True,
    delegation: Delegation | None = None, approval_wait: ApprovalWait | None = None,
) -> tuple[list[Observation], tuple[Tool, ...]]:
    """One run: offer the tools the token allows, then keep asking the agent
    for its next action until it stops. Returns what happened and what was
    offered.

    With a `delegation`, the delegated token's scopes are offered too, and
    tools marked `delegated` are called with that token, not the agent's own.

    With an `approval_wait`, a call the gateway holds for a person's approval
    is waited on and repeated once approved. Without one it fails with a note.

    `enforce_offer=False` simulates a client that doesn't police itself (a
    buggy runner, or an attacker holding the token): any registered tool is
    sent to the API whether or not it was offered. Lab 08 uses it to show that
    the API's policy, not the runner's list, is what actually says no."""
    trace_id = trace_id or secrets.token_hex(16)
    tokens.get(trace_id)
    granted = tokens.granted_scope + (f" {delegation.scope}" if delegation else "")
    offered = tools_for_scopes(TOOLS, granted)
    by_name = {t.name: t for t in (offered if enforce_offer else TOOLS)}
    history: list[Observation] = []
    for _ in range(max_actions):
        action = agent.next_action(history)
        if action is None:
            break
        tool = by_name.get(action.tool)
        if tool is None:
            # The agent asked for something it was never offered. Refuse it
            # here; the request never reaches the API.
            history.append(Observation(action, False, error=f"tool '{action.tool}' is not offered to this agent"))
            continue
        token = delegation.token if delegation and tool.delegated else tokens.get(trace_id)
        history.append(execute(
            tool, action, token, api_http, api_url, trace_id,
            wait=approval_wait, token_for=lambda: tokens.get(trace_id),
        ))
    return history, offered


def run_schedule(
    agent: Agent, tokens: TokenManager, api_http: httpx.Client, api_url: str,
    *, ticks: int, interval: float, sleep: Callable[[float], None] = time.sleep,
    on_run: Callable[[int, list[Observation], tuple[Tool, ...]], None] = lambda *_: None,
    enforce_offer: bool = True,
) -> int:
    """Run the agent on a schedule, unattended. Returns the number of runs."""
    for n in range(ticks):
        history, offered = run_once(agent, tokens, api_http, api_url, enforce_offer=enforce_offer)
        on_run(n + 1, history, offered)
        if n + 1 < ticks:
            sleep(interval)
    return ticks


def do_next_task(
    agent: Agent, tokens: TokenManager, http: httpx.Client, idp_url: str, api_url: str,
    client_id: str, secret: str, *, scope: str = "notes:read",
) -> tuple[dict | None, list[Observation], tuple[Tool, ...]]:
    """Claim one pending task, act for the person who asked, and finish it.
    Returns `(task, history, offered)`, with `task` None when nothing was
    waiting. The task is completed even if the exchange fails, so the person's
    token never sits in the app's table longer than it has to."""
    agent_token = tokens.get(secrets.token_hex(16))
    task = claim_task(http, api_url, agent_token)
    if task is None:
        return None, [], ()
    try:
        delegation = exchange(http, idp_url, client_id, secret, task, scope)
        history, offered = run_once(agent, tokens, http, api_url, trace_id=task["trace_id"], delegation=delegation)
    finally:
        complete_task(http, api_url, tokens.get(task["trace_id"]), task["id"])
    return task, history, offered
