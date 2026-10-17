"""Waiting for a person. An elevated call comes back from the gateway as "pending
approval" instead of a result. The runner asks, politely and at a steady pace,
until the request is approved, denied or has lapsed, and then either repeats
the call with the approval token or gives up with the reason.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx


@dataclass
class ApprovalWait:
    """How long to wait and how often to ask. The clock and sleep are
    injectable so a test doesn't have to wait for real."""

    interval: float = 1.0
    timeout: float = 120.0
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    on_pending: Callable[[int, str], None] = lambda approval_id, tool: None


def wait_for_decision(
    http: httpx.Client, api_url: str, token_for: Callable[[], str], approval_id: int, tool: str, trace_id: str,
    wait: ApprovalWait,
) -> dict:
    """Poll until the request leaves `pending`. Returns the last answer, or
    `{"status": "timeout"}` if nobody decided within `wait.timeout`. The token
    is fetched fresh each time because a long wait outlives a two-minute one."""
    wait.on_pending(approval_id, tool)
    deadline = wait.clock() + wait.timeout
    while True:
        res = http.get(
            f"{api_url}/agent/approvals/{approval_id}",
            headers={"Authorization": f"Bearer {token_for()}", "X-Trace-Id": trace_id},
        )
        res.raise_for_status()
        body = res.json()
        if body["status"] != "pending":
            return body
        if wait.clock() >= deadline:
            return {"status": "timeout"}
        wait.sleep(wait.interval)
