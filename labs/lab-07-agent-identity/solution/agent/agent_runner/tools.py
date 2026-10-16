"""The tools an agent can use, and which of them a given token may be offered.

A tool is a thing the agent can ask the runner to do: one HTTP call against
the capstone API, needing one scope. The runner, not the agent, makes the
call, and attaches the agent's own bearer token when it does.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    scope: str      # the OAuth scope the endpoint needs
    method: str
    path: str
    params: tuple[str, ...] = ()   # names of the JSON body fields the tool takes


TOOLS: tuple[Tool, ...] = (
    Tool("get_stats", "Read aggregate counts of users and notes.", "stats:read", "GET", "/internal/stats"),
    Tool(
        "write_report", "Leave a titled report for the humans who sponsor you.",
        "reports:write", "POST", "/agent/reports", params=("title", "body"),
    ),
    # Registered so the runner knows about it, but no agent in this course is
    # ever granted `admin:users`. Whether it gets *offered* is the point of
    # `tools_for_scopes` below.
    Tool("list_users", "List every user and their role.", "admin:users", "GET", "/admin/users"),
)


def tools_for_scopes(tools: tuple[Tool, ...], granted_scope: str) -> tuple[Tool, ...]:
    """Which tools should this agent be offered, given the scopes on its token?

    "Offered" is stricter than "will be allowed": an agent, especially one
    driven by a language model, can only ask for tools it has been told exist.
    """
    # LAB:SOLUTION >>>
    granted = set(granted_scope.split())
    return tuple(t for t in tools if t.scope in granted)
    # LAB:SOLUTION <<<
    # LAB:STARTER >>>
    # TODO(lab-07): this offers every tool no matter what the token grants. The
    # API would still refuse the ones outside the agent's scopes, but an
    # agent that can see `list_users` will try it, and a model will be
    # tempted by it. Offer only the tools whose `scope` appears in the
    # space-separated `granted_scope` string (compare whole scope names).
    return tools
    # LAB:STARTER <<<
