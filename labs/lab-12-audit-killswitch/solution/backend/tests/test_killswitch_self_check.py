"""Self-check suite for lab 12: one trace, one kill-switch.

    pytest tests/test_killswitch_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 12
handout. The three groups map to the three tasks:

  1. A cut-off that follows the chain         (idp/lab_idp/oauth.py: token_cut_off)
  2. One timeline from two services           (app/traces.py: correlate)
  3. Ending what a dead agent left behind     (app/approvals.py: cut_off_pending_work)
"""

import time

import pytest
from fastapi.testclient import TestClient

from agent_runner.agent import ArchiveAgent, NotesSummaryAgent
from agent_runner.auth import TokenManager
from agent_runner.delegation import TOKEN_EXCHANGE, Delegation, claim_handoff
from agent_runner.runner import do_next_handoff, do_next_task_and_hand_off, run_once
from app import approvals, traces
from app.main import app, audit_log, conn
from helpers import ensure_opa, full_login
from lab_idp import oauth

TIDY = ("tidy-agent", "tidy-agent-secret-do-not-reuse")
ARCHIVE = ("archive-agent", "archive-agent-secret-do-not-reuse")
RS = ("lab-resource-server", "lab-resource-server-secret-do-not-reuse")
IDP_URL, API = "http://localhost:9000", "http://localhost:8000"


@pytest.fixture(autouse=True)
def _opa():
    ensure_opa()


@pytest.fixture(autouse=True)
def _everyone_restored(idp):
    """A cut-off lasts until someone lifts it, so every test starts and ends clean."""
    for who in ("tidy-agent", "archive-agent"):
        idp.post(f"/agents/{who}/restore", data={"by": "test"}, auth=RS)
    yield
    for who in ("tidy-agent", "archive-agent"):
        idp.post(f"/agents/{who}/restore", data={"by": "test"}, auth=RS)


class Router:
    def __init__(self, idp, api):
        self._idp, self._api = idp, api

    def request(self, method, url, **kw):
        return (self._idp if url.startswith(IDP_URL) else self._api).request(method, url, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def person(idp, username="alice"):
    c = TestClient(app, follow_redirects=False)
    full_login(c, idp, username=username, password=f"{username}-lab-pass")
    return c


def admin():
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"}).status_code == 200
    return c


def ask(client, kind="archive_notes"):
    res = client.post("/agent/tasks", json={"kind": kind})
    assert res.status_code == 201, res.text
    task = conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (res.json()["id"],)).fetchone()
    return res.json(), task["subject_token"]


def introspect(idp, token):
    return idp.post("/introspect", data={"token": token}, auth=RS).json()


def exchange(idp, subject, scope, audience="", auth=TIDY):
    data = {"grant_type": TOKEN_EXCHANGE, "subject_token": subject, "scope": scope, **({"audience": audience} if audience else {})}
    return idp.post("/token", data=data, auth=auth)


def tidy_token(idp):
    _, subject = ask(person(idp))
    return exchange(idp, subject, "notes:read notes:write").json()["access_token"]


def own_token(idp, auth=TIDY, scope="stats:read"):
    return idp.post("/token", data={"grant_type": "client_credentials", "scope": scope}, auth=auth)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def cut_off(idp, who):
    assert idp.post(f"/agents/{who}/cut-off", data={"by": "test", "reason": "test"}, auth=RS).status_code == 200


# --- task 1: a cut-off that follows the chain --------------------------------------

def test_a_token_issued_to_a_cut_off_client_is_cut_off():
    assert oauth.token_cut_off({"client_id": "tidy-agent"}, {"tidy-agent"})


def test_a_token_whose_acting_agent_is_cut_off_is_cut_off():
    assert oauth.token_cut_off({"client_id": "x", "acting_as": {"sub": "tidy-agent"}}, {"tidy-agent"})


def test_a_token_that_came_through_a_cut_off_agent_is_cut_off():
    claims = {"client_id": "archive-agent", "acting_as": {"sub": "archive-agent", "via": ["tidy-agent"]}}
    reason = oauth.token_cut_off(claims, {"tidy-agent"})
    assert reason and "tidy-agent" in reason


def test_a_token_with_nobody_cut_off_is_fine():
    claims = {"client_id": "archive-agent", "acting_as": {"sub": "archive-agent", "via": ["tidy-agent"]}}
    assert oauth.token_cut_off(claims, set()) is None
    assert oauth.token_cut_off(claims, {"somebody-else"}) is None
    assert oauth.token_cut_off({"client_id": "x"}, {"y"}) is None


def test_the_reason_names_the_agent_that_was_cut_off():
    assert "tidy-agent" in oauth.token_cut_off({"client_id": "tidy-agent"}, {"tidy-agent"})
    assert "archive-agent" in oauth.token_cut_off({"client_id": "z", "acting_as": {"sub": "archive-agent"}}, {"archive-agent"})


def test_cutting_off_an_agent_stops_every_token_it_holds(idp):
    own, delegated = own_token(idp).json()["access_token"], tidy_token(idp)
    assert introspect(idp, own)["active"] and introspect(idp, delegated)["active"]
    cut_off(idp, "tidy-agent")
    assert not introspect(idp, own)["active"] and not introspect(idp, delegated)["active"]


def test_cutting_off_the_first_agent_also_kills_the_token_it_handed_to_the_second(idp):
    hop = exchange(idp, tidy_token(idp), "notes:read", audience="archive-agent").json()["access_token"]
    assert introspect(idp, hop)["active"]
    cut_off(idp, "tidy-agent")
    assert not introspect(idp, hop)["active"]


def test_cutting_off_the_second_agent_leaves_the_first_alone(idp):
    first = tidy_token(idp)
    cut_off(idp, "archive-agent")
    assert introspect(idp, first)["active"]


def test_a_cut_off_agent_cannot_get_a_new_token_or_act_for_anyone(idp):
    _, subject = ask(person(idp))
    cut_off(idp, "tidy-agent")
    assert own_token(idp).status_code == 401
    assert exchange(idp, subject, "notes:read").status_code == 400


def test_nothing_can_be_handed_to_a_cut_off_agent(idp):
    first = tidy_token(idp)
    cut_off(idp, "archive-agent")
    assert exchange(idp, first, "notes:read", audience="archive-agent").status_code == 400


def test_restoring_an_agent_lets_it_work_again(idp):
    cut_off(idp, "tidy-agent")
    assert own_token(idp).status_code == 401
    idp.post("/agents/tidy-agent/restore", data={"by": "test"}, auth=RS)
    assert own_token(idp).status_code == 200


def test_the_switch_needs_a_resource_servers_credentials_and_only_works_on_agents(idp):
    assert idp.post("/agents/tidy-agent/cut-off", data={"by": "x"}).status_code == 401
    assert idp.post("/agents/tidy-agent/cut-off", data={"by": "x"}, auth=("lab-resource-server", "wrong")).status_code == 401
    assert idp.post("/agents/digest-service/cut-off", data={"by": "x"}, auth=RS).status_code == 404
    assert own_token(idp, ("digest-service", "digest-service-secret-do-not-reuse")).status_code == 200


# --- task 2: one timeline from two services ----------------------------------------

def ev(trace, ts, action, actor=("human", "idp-alice"), decision="allow"):
    return {"trace_id": trace, "ts": ts, "action": action, "actor_type": actor[0], "actor_id": actor[1], "decision": decision}


def test_the_timeline_keeps_only_this_traces_rows():
    out = traces.correlate("t1", [ev("t1", 1, "a"), ev("t2", 2, "b")], [ev("t1", 3, "c"), ev(None, 4, "d")])
    assert [e["action"] for e in out] == ["a", "c"]


def test_the_timeline_is_in_the_order_things_happened_across_both_services():
    out = traces.correlate("t", [ev("t", 5, "late"), ev("t", 1, "early")], [ev("t", 3, "middle")])
    assert [e["action"] for e in out] == ["early", "middle", "late"]


def test_each_row_says_which_service_it_came_from():
    out = traces.correlate("t", [ev("t", 1, "a")], [ev("t", 2, "b")])
    assert [(e["action"], e["source"]) for e in out] == [("a", "app"), ("b", "idp")]


def test_introspection_noise_is_dropped():
    out = traces.correlate("t", [ev("t", 1, "oidc_introspect", ("service", "lab-resource-server")), ev("t", 2, "real")], [])
    assert [e["action"] for e in out] == ["real"]


def test_participants_are_listed_once_each_in_the_order_they_acted():
    events = [ev("t", 1, "a"), ev("t", 2, "b", ("agent", "tidy-agent")), ev("t", 3, "c"), ev("t", 4, "d", ("service", "digest-service")),
              ev("t", 5, "e", ("agent", "anonymous"))]
    assert traces.participants(events) == [
        {"kind": "human", "id": "idp-alice"}, {"kind": "agent", "id": "tidy-agent"}, {"kind": "service", "id": "digest-service"},
    ]


def test_the_recent_traces_list_counts_denials_and_names_who_took_part():
    rows = traces.summarise([ev("t1", 1, "a"), ev("t1", 2, "b", ("agent", "x"), "deny"), ev("t2", 9, "c"), ev("t1", 3, "oidc_introspect")])
    assert [r["trace_id"] for r in rows] == ["t2", "t1"]
    t1 = rows[1]
    assert t1["events"] == 2 and t1["denied"] == 1 and [p["id"] for p in t1["participants"]] == ["idp-alice", "x"]


def run_job(idp, *, kill_before_archive=None):
    """Alice asks, the tidy agent acts and hands the filing on, the archive agent does it."""
    alice = person(idp)
    alice.post("/notes", json={"title": "kept note", "body": "b"})
    ticket, _ = ask(alice)
    http = Router(idp, TestClient(app))
    tidy = TokenManager(http, IDP_URL, *TIDY, "stats:read reports:write")
    while True:
        task, _, _ = do_next_task_and_hand_off(NotesSummaryAgent(), tidy, http, IDP_URL, API, *TIDY)
        if task is None or task["id"] == ticket["id"]:
            break
    if kill_before_archive:
        kill_before_archive(ticket)
    archive = TokenManager(http, IDP_URL, *ARCHIVE, "reports:write")
    while True:
        work, history, _ = do_next_handoff(ArchiveAgent(), archive, http, API)
        if work is None or work["trace_id"] == ticket["trace_id"]:
            return alice, ticket, work, history


def test_an_admin_reads_one_trace_that_spans_the_human_both_agents_and_the_idp(idp):
    _, ticket, _, _ = run_job(idp)
    body = admin().get(f"/traces/{ticket['trace_id']}").json()
    assert {p["kind"] for p in body["participants"]} >= {"human", "agent"}
    assert [(h["role"], h["id"]) for h in body["chain"]][:3] == [("human", "idp-alice"), ("agent", "tidy-agent"), ("agent", "archive-agent")]
    assert {e["source"] for e in body["events"]} == {"app", "idp"}
    assert all(e["trace_id"] == ticket["trace_id"] for e in body["events"])
    stamps = [e["ts"] for e in body["events"]]
    assert stamps == sorted(stamps)
    assert not any(e["action"] == "oidc_introspect" for e in body["events"])


def test_the_recent_traces_list_includes_the_job(idp):
    _, ticket, _, _ = run_job(idp)
    rows = admin().get("/traces").json()
    row = next(r for r in rows if r["trace_id"] == ticket["trace_id"])
    assert {"tidy-agent", "archive-agent"} <= {p["id"] for p in row["participants"] if p["kind"] == "agent"}


def test_traces_are_for_admins_only_and_unknown_ones_are_not_found(idp):
    _, ticket, _, _ = run_job(idp)
    alice = person(idp)
    assert alice.get(f"/traces/{ticket['trace_id']}").status_code == 403
    assert alice.get("/traces").status_code == 403
    assert admin().get("/traces/" + "0" * 32).status_code == 404
    assert admin().get("/traces/not-a-trace").status_code == 404


# --- the kill-switch through the app -----------------------------------------------

def kill(client, agent, reason="", trace_id=None):
    return client.post(f"/agents/{agent}/kill", json={"reason": reason, "trace_id": trace_id})


def seen(idp):
    """Make sure the app has met both agents."""
    run_job(idp)


def test_an_admin_cuts_an_agent_off_and_its_very_next_tool_call_is_refused(idp):
    seen(idp)
    token = own_token(idp, scope="stats:read reports:write").json()["access_token"]
    assert TestClient(app).post("/agent/tools/get_stats", json={"args": {}}, headers=bearer(token)).status_code == 200
    assert kill(admin(), "tidy-agent", "looks wrong").json()["cut_off"] is True
    res = TestClient(app).post("/agent/tools/get_stats", json={"args": {}}, headers=bearer(token))
    assert res.status_code == 401 and "not active" in res.json()["detail"]


def test_cutting_off_the_first_agent_before_the_second_collects_leaves_the_second_nothing_to_do(idp):
    _, _, work, history = run_job(idp, kill_before_archive=lambda t: kill(admin(), "tidy-agent", "stop", t["trace_id"]))
    assert work is None and history == []


def test_cutting_off_the_first_agent_after_the_second_has_started_stops_the_seconds_next_call(idp):
    alice = person(idp)
    ticket, _ = ask(alice)
    http = Router(idp, TestClient(app))
    tidy = TokenManager(http, IDP_URL, *TIDY, "stats:read reports:write")
    while True:
        task, _, _ = do_next_task_and_hand_off(NotesSummaryAgent(), tidy, http, IDP_URL, API, *TIDY)
        if task is None or task["id"] == ticket["id"]:
            break
    archive = TokenManager(http, IDP_URL, *ARCHIVE, "reports:write")
    while (handoff := claim_handoff(http, API, archive.get("d" * 32))) and handoff["trace_id"] != ticket["trace_id"]:
        pass
    assert handoff, "the archive agent should have been handed the job"
    kill(admin(), "tidy-agent", "stop", ticket["trace_id"])
    delegation = Delegation(handoff["token"], handoff["scope"], handoff["id"], handoff["trace_id"])
    history, _ = run_once(ArchiveAgent(), archive, http, API, trace_id=handoff["trace_id"], delegation=delegation)
    assert history[0].action.tool == "read_notes" and history[0].ok is False and "not active" in history[0].error


def test_the_cut_off_appears_in_the_trace_it_interrupted(idp):
    _, ticket, _, _ = run_job(idp, kill_before_archive=lambda t: kill(admin(), "tidy-agent", "stop", t["trace_id"]))
    body = admin().get(f"/traces/{ticket['trace_id']}").json()
    kills = [e for e in body["events"] if e["action"] == "kill_agent"]
    assert kills and kills[0]["actor_type"] == "human" and kills[0]["decision"] == "allow"
    assert any(e["action"] == "cut_off_agent" and e["source"] == "idp" for e in body["events"])


def test_the_agents_sponsor_may_cut_it_off_but_an_ordinary_user_may_not(idp):
    seen(idp)
    carol = kill(person(idp, "carol"), "tidy-agent")
    assert carol.status_code == 403
    assert own_token(idp).status_code == 200
    ev = [e for e in audit_log.recent(100) if e.action == "kill_agent"][0]
    assert ev.decision == "deny" and ev.actor_id == "idp-carol"
    assert kill(person(idp, "alice"), "tidy-agent").status_code == 200   # alice sponsors tidy-agent
    assert own_token(idp).status_code == 401


def test_a_sponsor_cannot_cut_off_someone_elses_agent(idp):
    seen(idp)
    assert kill(person(idp, "bob"), "tidy-agent").status_code == 403    # bob sponsors archive-agent
    assert kill(person(idp, "bob"), "archive-agent").status_code == 200


def test_an_agent_the_app_has_never_seen_cannot_be_cut_off_by_name(idp):
    assert kill(admin(), "no-such-agent").status_code == 404


def test_the_agent_dashboard_shows_who_is_cut_off_and_only_an_admin_can_restore(idp):
    seen(idp)
    kill(admin(), "archive-agent")
    agents = {a["client_id"]: a for a in admin().get("/agent-activity").json()["agents"]}
    assert agents["archive-agent"]["cut_off"] is True and agents["tidy-agent"]["cut_off"] is False
    assert person(idp, "bob").post("/agents/archive-agent/restore").status_code == 403
    assert admin().post("/agents/archive-agent/restore").status_code == 200
    assert own_token(idp, ARCHIVE, "reports:write").status_code == 200


# --- task 3: ending what a dead agent left behind -------------------------------------

def test_cutting_off_an_agent_ends_its_pending_approval_requests(idp):
    seen(idp)
    token = own_token(idp, scope="stats:read reports:write reports:purge").json()["access_token"]
    res = TestClient(app).post("/agent/tools/purge_reports", json={"args": {"keep_latest": "1"}}, headers=bearer(token))
    approval_id = res.json()["approval_id"]
    assert kill(admin(), "tidy-agent").json()["ended"] >= 1
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    assert row["status"] == "expired" and row["approval_token"] is None and row["decided_by"] == "kill-switch"
    assert admin().post(f"/approvals/{approval_id}/decide", json={"decision": "approve"}).status_code == 409


def test_an_approval_already_granted_is_ended_too_and_its_token_wiped(idp):
    seen(idp)
    token = own_token(idp, scope="stats:read reports:write reports:purge").json()["access_token"]
    approval_id = TestClient(app).post("/agent/tools/purge_reports", json={"args": {"keep_latest": "1"}}, headers=bearer(token)).json()["approval_id"]
    admin().post(f"/approvals/{approval_id}/decide", json={"decision": "approve"})
    assert conn.execute("SELECT approval_token FROM approvals WHERE id = ?", (approval_id,)).fetchone()["approval_token"]
    kill(admin(), "tidy-agent")
    row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    assert row["status"] == "expired" and row["approval_token"] is None


def test_cutting_off_the_first_agent_cancels_a_hand_off_it_made_and_wipes_the_token(idp):
    seen(idp)
    alice = person(idp)
    ticket, _ = ask(alice)
    http = Router(idp, TestClient(app))
    tidy = TokenManager(http, IDP_URL, *TIDY, "stats:read reports:write")
    while True:
        task, _, _ = do_next_task_and_hand_off(NotesSummaryAgent(), tidy, http, IDP_URL, API, *TIDY)
        if task is None or task["id"] == ticket["id"]:
            break
    handoff_id = task["handoff_id"]
    kill(admin(), "tidy-agent")
    row = conn.execute("SELECT * FROM agent_handoffs WHERE id = ?", (handoff_id,)).fetchone()
    assert row["status"] == "cancelled" and row["token"] is None


def test_cutting_off_an_agent_cancels_a_task_it_claimed_and_wipes_the_persons_token(idp):
    seen(idp)
    alice = person(idp)
    ticket, _ = ask(alice, "summarise_notes")
    token = own_token(idp, scope="stats:read reports:write").json()["access_token"]
    api = TestClient(app)
    while (task := api.get("/agent/tasks/next", headers=bearer(token)).json()["task"]) and task["id"] != ticket["id"]:
        pass
    assert task and task["subject_token"]
    kill(admin(), "tidy-agent")
    row = conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (ticket["id"],)).fetchone()
    assert row["status"] == "cancelled" and row["subject_token"] is None


def test_finished_work_and_other_agents_work_are_left_alone(idp):
    seen(idp)
    done = conn.execute("SELECT COUNT(*) AS n FROM agent_handoffs WHERE status = 'done'").fetchone()["n"]
    tok = own_token(idp, ARCHIVE, "reports:write").json()["access_token"]
    kill(admin(), "tidy-agent")
    assert conn.execute("SELECT COUNT(*) AS n FROM agent_handoffs WHERE status = 'done'").fetchone()["n"] == done
    assert introspect(idp, tok)["active"]


def test_the_count_says_how_many_things_were_ended(idp):
    seen(idp)
    now = time.time()
    n1 = approvals.cut_off_pending_work(conn, "tidy-agent", now)
    assert approvals.cut_off_pending_work(conn, "tidy-agent", now) == 0 and n1 >= 0
