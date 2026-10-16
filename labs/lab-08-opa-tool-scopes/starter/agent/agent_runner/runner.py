"""Runs an agent: offers it tools, executes what it asks for with the
agent's own token, and records what happened."""

import secrets
import time
from collections.abc import Callable

import httpx

from .agent import Action, Agent, Observation
from .auth import TokenManager
from .tools import TOOLS, Tool, tools_for_scopes


def execute(tool: Tool, action: Action, token: str, api_http: httpx.Client, api_url: str, trace_id: str) -> Observation:
    headers = {"Authorization": f"Bearer {token}", "X-Trace-Id": trace_id}
    body = {"args": {k: str(action.args.get(k, "")) for k in tool.params}}
    res = api_http.request(tool.method, f"{api_url}{tool.path}", headers=headers, json=body)
    try:
        payload = res.json()
    except ValueError:
        payload = None
    if res.status_code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) else res.text
        return Observation(action, False, error=f"{res.status_code}: {detail}")
    return Observation(action, True, result=payload)


def run_once(
    agent: Agent, tokens: TokenManager, api_http: httpx.Client, api_url: str,
    *, trace_id: str | None = None, max_actions: int = 10, enforce_offer: bool = True,
) -> tuple[list[Observation], tuple[Tool, ...]]:
    """One run: offer the tools the token allows, then keep asking the agent
    for its next action until it stops. Returns what happened and what was
    offered.

    `enforce_offer=False` simulates a client that doesn't police itself (a
    buggy runner, or an attacker holding the token): any registered tool is
    sent to the API whether or not it was offered. Lab 08 uses it to show that
    the API's policy, not the runner's list, is what actually says no."""
    trace_id = trace_id or secrets.token_hex(16)
    tokens.get(trace_id)
    offered = tools_for_scopes(TOOLS, tokens.granted_scope)
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
        history.append(execute(tool, action, tokens.get(trace_id), api_http, api_url, trace_id))
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
