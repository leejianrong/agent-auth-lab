"""Trace-ID helpers.

IDs are shaped like OpenTelemetry's (32 hex chars for a trace ID, 16 hex
chars for a span ID) so the concept transfers directly if a learner adopts
real OpenTelemetry later. This package does not depend on the `opentelemetry`
SDK — it only borrows the ID shape.
"""

import secrets
from contextlib import contextmanager
from contextvars import ContextVar

_current_trace_id: ContextVar[str | None] = ContextVar("current_trace_id", default=None)


def new_trace_id() -> str:
    """Generate a new 32-hex-character trace ID (OTel trace-ID shape)."""
    return secrets.token_hex(16)


def new_span_id() -> str:
    """Generate a new 16-hex-character span ID (OTel span-ID shape)."""
    return secrets.token_hex(8)


def current_trace_id() -> str | None:
    """Return the trace ID active in the current context, if any."""
    return _current_trace_id.get()


@contextmanager
def trace_context(trace_id: str | None = None):
    """Bind a trace ID for the duration of the `with` block.

    Reuses `trace_id` if given (continuing a trace across a hop, e.g. an
    agent calling a downstream API), otherwise starts a new one.
    """
    token = _current_trace_id.set(trace_id or new_trace_id())
    try:
        yield _current_trace_id.get()
    finally:
        _current_trace_id.reset(token)
