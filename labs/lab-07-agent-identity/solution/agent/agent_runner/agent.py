"""The agent interface (ADR-0005).

An agent is anything that, shown what has happened so far, says what to do
next. A scripted agent follows a fixed plan. A language-model agent asks a
model. The runner treats them identically, so swapping one for the other
changes nothing about identity, tokens or audit.
"""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Action:
    tool: str
    args: dict = field(default_factory=dict)


@dataclass
class Observation:
    """What came back from one action. `ok` is False when the runner refused
    the action or the API did."""

    action: Action
    ok: bool
    result: dict | None = None
    error: str | None = None


class Agent(Protocol):
    name: str

    def next_action(self, history: list[Observation]) -> Action | None:
        """Return the next thing to do, or None when finished."""


class ScriptedAgent:
    """Deterministic: read the stats, then write a report about them. No model,
    no randomness, so a lab's checks can be exact (ADR-0005)."""

    name = "scripted"

    def next_action(self, history: list[Observation]) -> Action | None:
        if not history:
            return Action("get_stats")
        if len(history) == 1:
            stats = history[0].result or {}
            body = f"{stats.get('users', '?')} users and {stats.get('notes', '?')} notes at last count."
            return Action("write_report", {"title": "Tidy agent: status", "body": body})
        return None
