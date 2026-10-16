"""Asking Open Policy Agent whether an agent may make a tool call (ADR-0007).

OPA runs next to the app as a sidecar, with the Rego policy in `policy/`
loaded. The app sends it one JSON document per decision and gets one back. The
app enforces; OPA decides. Neither knows how the other works inside.

    LAB_OPA_URL   where the sidecar listens (default http://localhost:8181)
"""

import os
from dataclasses import dataclass

import httpx

OPA_URL = os.environ.get("LAB_OPA_URL", "http://localhost:8181")
DECISION_PATH = "/v1/data/agentauth/tools/decision"

_http = httpx.Client(timeout=2.0)


def set_opa_url(url: str) -> None:
    """Point the client at a different sidecar (the self-check starts its own)."""
    global OPA_URL
    OPA_URL = url


@dataclass(frozen=True)
class Decision:
    """OPA's answer: allow or deny, and which named policies decided it."""

    allow: bool
    policies: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def summary(self) -> str:
        return f"{', '.join(self.policies)}: {'; '.join(self.reasons)}"


def build_input(actor, result: dict, tool_name: str, args: dict) -> dict:
    """The document OPA decides on. The agent and its capabilities come from
    the introspected token, which the IdP vouches for. Only `tool` comes from
    the request, because that is the one thing the caller is asking for."""
    return {
        "agent": {"id": actor.id, "sponsor": actor.sponsor},
        "capabilities": result.get("capabilities") or [],
        "tool": {"name": tool_name, "args": args},
    }


def decision_from_opa(body: dict | None) -> Decision:
    """Turn OPA's HTTP answer into a `Decision`. `body` is the parsed JSON, or
    None when OPA could not be reached or answered with an error.

    A healthy answer looks like `{"result": {"allow": false, "policies": [...],
    "reasons": [...]}}`. If the policy has no answer for this input, OPA
    replies `{}`. Either way, the call is only allowed when OPA clearly said
    so."""
    if body is None:
        return Decision(False, ("policy-engine-unreachable",), ("the policy engine could not be reached, so the call is denied",))
    result = body.get("result")
    if not isinstance(result, dict):
        return Decision(False, ("policy-engine-no-decision",), ("the policy engine returned no decision, so the call is denied",))
    return Decision(result.get("allow") is True, tuple(result.get("policies", ())), tuple(result.get("reasons", ())))


def decide(input_doc: dict) -> Decision:
    try:
        res = _http.post(f"{OPA_URL}{DECISION_PATH}", json={"input": input_doc})
        body = res.json() if res.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        body = None
    return decision_from_opa(body)
