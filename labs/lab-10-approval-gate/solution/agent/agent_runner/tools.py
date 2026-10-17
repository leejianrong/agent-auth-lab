"""The tools an agent can use, and which of them a given token may be offered.

A tool is a thing the agent can ask the runner to do: one call to the capstone
API's tool gateway, needing one scope. The runner, not the agent, makes the
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
    delegated: bool = False        # lab 09: called with a token for acting on a person's behalf, not the agent's own


TOOLS: tuple[Tool, ...] = (
    Tool("get_stats", "Read aggregate counts of users and notes.", "stats:read", "POST", "/agent/tools/get_stats"),
    Tool(
        "write_report", "Leave a titled report for the humans who sponsor you.",
        "reports:write", "POST", "/agent/tools/write_report", params=("title", "body"),
    ),
    # Lab 09: this one reaches a downstream API for a person. The agent's own
    # token never carries `notes:read`; only a delegated token does, so the tool
    # is only offered during a delegated task.
    Tool(
        "read_notes", "Read the notes of the person you are acting for.",
        "notes:read", "GET", "/delegated/notes", delegated=True,
    ),
    # Lab 10: irreversible, so the policy holds every call for a person's yes.
    # The runner doesn't know that; it only knows how to wait when the gateway
    # answers "pending approval".
    Tool(
        "purge_reports", "Delete old reports, keeping only the newest few.",
        "reports:purge", "POST", "/agent/tools/purge_reports", params=("keep_latest",),
    ),
    # Registered so the runner knows about it, but no agent in this course is
    # ever granted `admin:users`. Whether it gets *offered* is the point of
    # `tools_for_scopes` below, and whether it would be *allowed* is the point
    # of the policy in lab 08.
    Tool("list_users", "List every user and their role.", "admin:users", "POST", "/agent/tools/list_users"),
)


def tools_for_scopes(tools: tuple[Tool, ...], granted_scope: str) -> tuple[Tool, ...]:
    """Which tools should this agent be offered, given the scopes on its token?

    "Offered" is stricter than "will be allowed": an agent, especially one
    driven by a language model, can only ask for tools it has been told exist.
    """
    granted = set(granted_scope.split())
    return tuple(t for t in tools if t.scope in granted)
