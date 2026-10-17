"""Reading one trace across every service and every kind of identity.

An action in this system leaves audit rows in more than one place: the app's
own log and the IdP's. They share a trace id, because the id travels with the
request from the browser to the app, to the IdP and back, and on from agent to
agent. Putting them together is the whole of "unified audit".
"""


def correlate(trace_id: str, app_events: list[dict], idp_events: list[dict]) -> list[dict]:
    """One timeline for `trace_id`. `app_events` and `idp_events` are audit rows
    as dicts, each with a `trace_id`, a timestamp `ts` and an `action`. Tag each
    row with where it came from (`source`: "app" or "idp"), keep only rows of this
    trace, drop the introspection calls (they happen on every hop and say nothing
    about who acted), and put the rest in the order they happened."""
    tagged = [{**e, "source": "app"} for e in app_events] + [{**e, "source": "idp"} for e in idp_events]
    mine = [e for e in tagged if e.get("trace_id") == trace_id and e["action"] != "oidc_introspect"]
    return sorted(mine, key=lambda e: e["ts"])


def participants(events: list[dict]) -> list[dict]:
    """Who appears in a trace, once each, in the order they first acted: humans,
    services and agents side by side."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for e in events:
        key = (e["actor_type"], e["actor_id"])
        if key not in seen and e["actor_id"] not in ("anonymous", "unknown"):
            seen.add(key)
            out.append({"kind": e["actor_type"], "id": e["actor_id"]})
    return out


def summarise(events: list[dict]) -> list[dict]:
    """The recent-traces list: one row per trace id, newest first."""
    by_trace: dict[str, list[dict]] = {}
    for e in events:
        if e.get("trace_id") and e["action"] != "oidc_introspect":
            by_trace.setdefault(e["trace_id"], []).append(e)
    rows = []
    for trace_id, evs in by_trace.items():
        evs.sort(key=lambda e: e["ts"])
        rows.append({
            "trace_id": trace_id, "started": evs[0]["ts"], "ended": evs[-1]["ts"], "events": len(evs),
            "denied": sum(1 for e in evs if e["decision"] == "deny"), "participants": participants(evs),
            "first_action": evs[0]["action"],
        })
    return sorted(rows, key=lambda r: r["ended"], reverse=True)
