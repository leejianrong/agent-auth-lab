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


class ProbingAgent:
    """Deterministic, and badly behaved on purpose: it reads the stats, then
    tries a report far longer than its capability allows, then tries a tool it
    was never granted. Run it with the runner's offer check off to watch the
    API's policy refuse both."""

    name = "probing"

    def next_action(self, history: list[Observation]) -> Action | None:
        if not history:
            return Action("get_stats")
        if len(history) == 1:
            return Action("write_report", {"title": "Everything I know", "body": "lorem ipsum " * 40})
        if len(history) == 2:
            return Action("list_users")
        return None


class NotesSummaryAgent:
    """Deterministic: while acting for a person, read their notes, then leave a
    short report about them. The first action uses the delegated token, the
    second the agent's own."""

    name = "notes-summary"

    def next_action(self, history: list[Observation]) -> Action | None:
        if not history:
            return Action("read_notes")
        if len(history) == 1:
            data = history[0].result or {}
            titles = [n["title"] for n in data.get("notes", [])]
            body = f"{data.get('on_behalf_of', '?')} has {len(titles)} notes: " + ", ".join(titles)
            return Action("write_report", {"title": "Notes summary", "body": body[:180]})
        return None
