"""Structured audit logging, shared by every lab.

Every lab imports `AuditLog` instead of building its own logging table. The
schema is intentionally identity-agnostic — `actor_type` covers "human",
"service", and "agent" from lab 0 onward, even before agents show up, so
later labs don't need a schema migration.
"""

import json
import sqlite3
import secrets
import time
from dataclasses import asdict, dataclass, field

from .trace import current_trace_id, new_span_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    trace_id TEXT,
    span_id TEXT,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT,
    decision TEXT NOT NULL,
    reason TEXT,
    metadata_json TEXT NOT NULL
);
"""


@dataclass
class AuditEvent:
    id: str
    ts: float
    actor_type: str
    actor_id: str
    action: str
    decision: str
    trace_id: str | None = None
    span_id: str | None = None
    resource: str | None = None
    reason: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLog:
    """A structured, queryable audit trail backed by SQLite.

    `decision` is always one of "allow" or "deny" — there is no silent
    third option, because a denial that isn't recorded defeats the point of
    an audit trail.
    """

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def record(
        self,
        *,
        actor_type: str,
        actor_id: str,
        action: str,
        decision: str,
        resource: str | None = None,
        reason: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEvent:
        if decision not in ("allow", "deny"):
            raise ValueError(f"decision must be 'allow' or 'deny', got {decision!r}")

        event = AuditEvent(
            id=secrets.token_hex(8),
            ts=time.time(),
            trace_id=current_trace_id(),
            span_id=new_span_id(),
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            metadata=metadata or {},
        )
        self._conn.execute(
            """INSERT INTO audit_events
               (id, ts, trace_id, span_id, actor_type, actor_id, action,
                resource, decision, reason, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.ts,
                event.trace_id,
                event.span_id,
                event.actor_type,
                event.actor_id,
                event.action,
                event.resource,
                event.decision,
                event.reason,
                json.dumps(event.metadata),
            ),
        )
        self._conn.commit()
        return event

    def recent(self, limit: int = 100) -> list[AuditEvent]:
        rows = self._conn.execute(
            "SELECT id, ts, trace_id, span_id, actor_type, actor_id, action, "
            "resource, decision, reason, metadata_json "
            "FROM audit_events ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            AuditEvent(
                id=r[0],
                ts=r[1],
                trace_id=r[2],
                span_id=r[3],
                actor_type=r[4],
                actor_id=r[5],
                action=r[6],
                resource=r[7],
                decision=r[8],
                reason=r[9],
                metadata=json.loads(r[10]),
            )
            for r in rows
        ]

    def by_trace(self, trace_id: str) -> list[AuditEvent]:
        events = self.recent(limit=10_000)
        return [e for e in events if e.trace_id == trace_id]
