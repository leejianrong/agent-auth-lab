"""FastAPI router exposing the audit log to the dashboard UI.

Every lab mounts this the same way:

    from observability_harness import AuditLog
    from observability_harness.dashboard import create_dashboard_router

    audit_log = AuditLog("app.db")
    app.include_router(create_dashboard_router(audit_log), prefix="/observability")

The learner never has to write this endpoint or the dashboard that renders
it — it's provided infrastructure, not a taught concept.
"""

from fastapi import APIRouter, Query

from .audit import AuditLog


def create_dashboard_router(audit_log: AuditLog) -> APIRouter:
    router = APIRouter()

    @router.get("/events")
    def list_events(limit: int = Query(default=100, le=1000)):
        return [e.to_dict() for e in audit_log.recent(limit=limit)]

    @router.get("/traces/{trace_id}")
    def get_trace(trace_id: str):
        return [e.to_dict() for e in audit_log.by_trace(trace_id)]

    return router
