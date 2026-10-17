"""Self-check suite for lab 10: a human approves the elevated action.

    pytest tests/test_approval_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 10
handout. The three groups map to the three tasks:

  1. The request's state machine                          (app/approvals.py: transition)
  2. An approval token that belongs to one exact call     (app/approvals.py: approval_token_allowed)
  3. Who may decide                                       (app/approvals.py: may_decide)

Then the gate as a whole: the call that waits, the decision, the one-minute
token, and the audit trail that ties them together.
"""

import time

import pytest
from fastapi.testclient import TestClient

from agent_runner.agent import ScriptedAgent, TidyUpAgent
from agent_runner.approval import ApprovalWait
from agent_runner.auth import TokenManager
from agent_runner.runner import run_once
from app import approvals, opa_client
from app.main import app, audit_log, conn
from helpers import ensure_opa, full_login

AGENT = ("tidy-agent", "tidy-agent-secret-do-not-reuse")
IDP_URL, API = "http://localhost:9000", "http://localhost:8000"
SCOPE = "stats:read reports:write reports:purge"


@pytest.fixture(autouse=True)
def _opa():
    ensure_opa()


def agent_token(idp, scope=SCOPE):
    res = idp.post("/token", data={"grant_type": "client_credentials", "scope": scope}, auth=AGENT)
    assert res.status_code == 200
    return res.json()["access_token"]


def call(tool, args=None, *, token, trace_id=None, **extra):
    headers = {"Authorization": f"Bearer {token}", **({"X-Trace-Id": trace_id} if trace_id else {})}
    return TestClient(app).post(f"/agent/tools/{tool}", json={"args": args or {}, **extra}, headers=headers)


def poll(approval_id, token):
    return TestClient(app).get(f"/agent/approvals/{approval_id}", headers={"Authorization": f"Bearer {token}"})


def admin_client():
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"}).status_code == 200
    return c


def person_client(idp, username):
    c = TestClient(app, follow_redirects=False)
    full_login(c, idp, username=username, password=f"{username}-lab-pass")
    return c


def decide(client, approval_id, decision="approve", note=None):
    return client.post(f"/approvals/{approval_id}/decide", json={"decision": decision, "note": note})


def seed_reports(n=4):
    for i in range(n):
        conn.execute("INSERT INTO agent_reports (agent_id, title, body, created_at) VALUES ('tidy-agent', ?, 'x', ?)", (f"old {i}", time.time()))
    conn.commit()


def report_count():
    return conn.execute("SELECT COUNT(*) AS n FROM agent_reports").fetchone()["n"]


def ask_to_purge(idp, keep="1", trace_id=None):
    token = agent_token(idp)
    res = call("purge_reports", {"keep_latest": keep}, token=token, trace_id=trace_id)
    assert res.status_code == 202, res.text
    return token, res.json()["approval_id"]


def events(action):
    return [e for e in audit_log.recent(300) if e.action == action]


# --- task 1: the request's state machine ----------------------------------------

@pytest.mark.parametrize("status, event, expected", [
    ("pending", "approve", "approved"),
    ("pending", "deny", "denied"),
    ("pending", "expire", "expired"),
    ("approved", "use", "used"),
    ("approved", "expire", "expired"),
])
def test_the_allowed_transitions(status, event, expected):
    assert approvals.transition(status, event) == expected


@pytest.mark.parametrize("status", ["denied", "expired", "used"])
@pytest.mark.parametrize("event", ["approve", "deny", "use", "expire"])
def test_a_finished_request_cannot_move_again(status, event):
    with pytest.raises(approvals.InvalidTransition):
        approvals.transition(status, event)


def test_a_denied_request_cannot_be_approved_later():
    with pytest.raises(approvals.InvalidTransition):
        approvals.transition("denied", "approve")


def test_a_request_cannot_be_used_before_it_is_approved():
    with pytest.raises(approvals.InvalidTransition):
        approvals.transition("pending", "use")


def test_an_approved_request_cannot_be_decided_a_second_time():
    for event in ("approve", "deny"):
        with pytest.raises(approvals.InvalidTransition):
            approvals.transition("approved", event)


def test_an_event_the_gate_does_not_know_is_refused():
    with pytest.raises(approvals.InvalidTransition):
        approvals.transition("pending", "reopen")


# --- task 2: an approval token belongs to one exact call -------------------------

DIGEST = approvals.args_digest("purge_reports", {"keep_latest": "1"})


def row(**kw):
    return {"status": "approved", "approval_token": "tok-123", "token_expires_at": 1060.0, "agent_id": "tidy-agent",
            "tool": "purge_reports", "args_digest": DIGEST, **kw}


def check(r=None, *, presented="tok-123", agent="tidy-agent", tool="purge_reports", digest=DIGEST, now=1000.0):
    return approvals.approval_token_allowed(r or row(), presented, agent_id=agent, tool=tool, digest=digest, now=now)


def test_a_live_token_for_the_same_call_is_accepted():
    assert check() == (True, "approval accepted")


@pytest.mark.parametrize("status", ["pending", "denied", "expired", "used"])
def test_a_request_that_is_not_approved_is_refused(status):
    ok, reason = check(row(status=status))
    assert not ok and status in reason


def test_the_wrong_token_is_refused():
    ok, reason = check(presented="guess")
    assert not ok and "does not match" in reason


def test_a_request_with_no_stored_token_never_matches():
    assert not check(row(approval_token=None), presented="")[0]
    assert not check(row(approval_token=None), presented="None")[0]


def test_an_expired_token_is_refused_even_if_nothing_swept_it():
    ok, reason = check(now=1060.0)
    assert not ok and "expired" in reason


def test_an_approval_for_one_agent_cannot_be_spent_by_another():
    ok, reason = check(agent="other-agent")
    assert not ok and "different agent" in reason


def test_an_approval_for_one_tool_cannot_be_spent_on_another():
    ok, reason = check(tool="list_users")
    assert not ok and "different tool" in reason


def test_an_approval_for_one_set_of_arguments_cannot_be_spent_on_other_arguments():
    ok, reason = check(digest=approvals.args_digest("purge_reports", {"keep_latest": "0"}))
    assert not ok and "different arguments" in reason


def test_the_argument_fingerprint_ignores_key_order_but_not_values():
    assert approvals.args_digest("t", {"a": "1", "b": "2"}) == approvals.args_digest("t", {"b": "2", "a": "1"})
    assert approvals.args_digest("t", {"a": "1"}) != approvals.args_digest("t", {"a": "2"})


# --- task 3: who may decide ------------------------------------------------------

def test_an_admin_may_decide_any_request():
    assert approvals.may_decide(role="admin", idp_sub=None, sponsor="idp-alice")[0]


def test_the_agents_sponsor_may_decide_its_requests():
    assert approvals.may_decide(role="user", idp_sub="idp-alice", sponsor="idp-alice")[0]


def test_an_ordinary_user_may_not_decide():
    ok, reason = approvals.may_decide(role="user", idp_sub="idp-carol", sponsor="idp-alice")
    assert not ok and "admin or the agent's sponsor" in reason


def test_a_person_with_no_idp_identity_is_not_the_sponsor_of_an_agent_with_none():
    assert not approvals.may_decide(role="user", idp_sub=None, sponsor=None)[0]


def test_the_two_allowed_answers_have_different_reasons():
    assert approvals.may_decide(role="admin", idp_sub=None, sponsor="s")[1] != approvals.may_decide(role="user", idp_sub="s", sponsor="s")[1]


def test_a_user_who_is_neither_admin_nor_sponsor_cannot_decide_through_the_app(idp):
    _, approval_id = ask_to_purge(idp)
    res = decide(person_client(idp, "carol"), approval_id)
    assert res.status_code == 403
    assert conn.execute("SELECT status FROM approvals WHERE id = ?", (approval_id,)).fetchone()["status"] == "pending"
    ev = events("decide_approval")[0]
    assert ev.decision == "deny" and "admin or the agent's sponsor" in ev.reason


def test_the_queue_shows_a_person_only_what_they_may_decide(idp):
    _, approval_id = ask_to_purge(idp)
    assert approval_id not in [a["id"] for a in person_client(idp, "carol").get("/approvals").json()]
    assert approval_id in [a["id"] for a in person_client(idp, "alice").get("/approvals").json()]
    assert approval_id in [a["id"] for a in admin_client().get("/approvals").json()]


def test_the_sponsor_can_approve_their_agents_request(idp):
    token, approval_id = ask_to_purge(idp)
    assert decide(person_client(idp, "alice"), approval_id).status_code == 200
    assert poll(approval_id, token).json()["status"] == "approved"


# --- the gate as a whole ---------------------------------------------------------

def test_an_elevated_call_waits_instead_of_running(idp):
    seed_reports()
    before = report_count()
    res = call("purge_reports", {"keep_latest": "1"}, token=agent_token(idp))
    assert res.status_code == 202 and res.json()["status"] == "pending_approval"
    assert report_count() == before
    held = events("purge_reports")[0]
    assert held.decision == "deny" and "approve" in held.reason and held.metadata["approval_id"] == res.json()["approval_id"]


def test_asking_again_for_the_same_thing_does_not_queue_a_second_request(idp):
    token = agent_token(idp)
    first = call("purge_reports", {"keep_latest": "3"}, token=token).json()["approval_id"]
    assert call("purge_reports", {"keep_latest": "3"}, token=token).json()["approval_id"] == first
    assert call("purge_reports", {"keep_latest": "4"}, token=token).json()["approval_id"] != first


def test_while_it_waits_the_agent_gets_no_token(idp):
    token, approval_id = ask_to_purge(idp)
    body = poll(approval_id, token).json()
    assert body["status"] == "pending" and "approval_token" not in body


def test_approving_issues_a_token_that_lives_about_a_minute(idp):
    token, approval_id = ask_to_purge(idp)
    decide(admin_client(), approval_id)
    body = poll(approval_id, token).json()
    assert body["status"] == "approved" and body["approval_token"]
    assert 55 <= body["token_expires_at"] - time.time() <= 61


def test_the_queue_never_shows_the_token(idp):
    token, approval_id = ask_to_purge(idp)
    admin = admin_client()
    decide(admin, approval_id)
    assert "approval_token" not in str(admin.get("/approvals").json())
    assert poll(approval_id, token).json()["approval_token"] not in str(admin.get("/approvals").json())


def test_the_approved_call_runs_once_with_the_token_and_deletes_the_reports(idp):
    seed_reports(5)
    token, approval_id = ask_to_purge(idp, keep="2")
    decide(admin_client(), approval_id)
    approval_token = poll(approval_id, token).json()["approval_token"]
    res = call("purge_reports", {"keep_latest": "2"}, token=token, approval_id=approval_id, approval_token=approval_token)
    assert res.status_code == 200 and res.json()["kept"] == 2 and res.json()["deleted"] >= 3
    assert report_count() == 2
    ev = events("purge_reports")[0]
    assert ev.decision == "allow" and ev.metadata["approval_id"] == approval_id and ev.metadata["approved_by"] == "admin"


def test_an_approval_token_works_only_once(idp):
    seed_reports()
    token, approval_id = ask_to_purge(idp, keep="1")
    decide(admin_client(), approval_id)
    approval_token = poll(approval_id, token).json()["approval_token"]
    spend = lambda: call("purge_reports", {"keep_latest": "1"}, token=token, approval_id=approval_id, approval_token=approval_token)
    assert spend().status_code == 200
    again = spend()
    assert again.status_code == 403
    assert conn.execute("SELECT approval_token FROM approvals WHERE id = ?", (approval_id,)).fetchone()["approval_token"] is None


def test_an_approval_for_one_set_of_arguments_cannot_run_a_bigger_purge(idp):
    seed_reports()
    token, approval_id = ask_to_purge(idp, keep="3")
    decide(admin_client(), approval_id)
    approval_token = poll(approval_id, token).json()["approval_token"]
    before = report_count()
    res = call("purge_reports", {"keep_latest": "0"}, token=token, approval_id=approval_id, approval_token=approval_token)
    assert res.status_code == 403 and "different arguments" in res.json()["detail"]
    assert report_count() == before


def test_a_guessed_token_does_not_run_anything(idp):
    seed_reports()
    token, approval_id = ask_to_purge(idp)
    decide(admin_client(), approval_id)
    before = report_count()
    res = call("purge_reports", {"keep_latest": "1"}, token=token, approval_id=approval_id, approval_token="guess")
    assert res.status_code == 403 and report_count() == before


def test_a_denied_request_never_runs(idp):
    seed_reports()
    token, approval_id = ask_to_purge(idp)
    assert decide(admin_client(), approval_id, "deny", "not today").status_code == 200
    body = poll(approval_id, token).json()
    assert body["status"] == "denied" and "approval_token" not in body
    before = report_count()
    res = call("purge_reports", {"keep_latest": "1"}, token=token, approval_id=approval_id, approval_token="anything")
    assert res.status_code == 403 and report_count() == before


def test_a_decision_is_final(idp):
    _, approval_id = ask_to_purge(idp)
    admin = admin_client()
    assert decide(admin, approval_id, "deny").status_code == 200
    again = decide(admin, approval_id, "approve")
    assert again.status_code == 409
    assert conn.execute("SELECT status FROM approvals WHERE id = ?", (approval_id,)).fetchone()["status"] == "denied"


def test_a_request_nobody_answers_lapses_and_can_no_longer_be_approved(idp):
    token, approval_id = ask_to_purge(idp)
    conn.execute("UPDATE approvals SET expires_at = ? WHERE id = ?", (time.time() - 1, approval_id))
    conn.commit()
    assert poll(approval_id, token).json()["status"] == "expired"
    assert decide(admin_client(), approval_id).status_code == 409
    ev = events("approval_expired")[0]
    assert ev.decision == "deny" and ev.metadata["approval_id"] == approval_id


def test_an_approval_that_is_not_used_in_time_stops_working(idp):
    seed_reports()
    token, approval_id = ask_to_purge(idp)
    decide(admin_client(), approval_id)
    approval_token = poll(approval_id, token).json()["approval_token"]
    conn.execute("UPDATE approvals SET token_expires_at = ? WHERE id = ?", (time.time() - 1, approval_id))
    conn.commit()
    before = report_count()
    res = call("purge_reports", {"keep_latest": "1"}, token=token, approval_id=approval_id, approval_token=approval_token)
    assert res.status_code == 403 and report_count() == before
    assert conn.execute("SELECT approval_token FROM approvals WHERE id = ?", (approval_id,)).fetchone()["approval_token"] is None


def test_the_request_the_decision_and_the_spend_share_one_trace(idp):
    trace = "ab" * 16
    seed_reports()
    token, approval_id = ask_to_purge(idp, keep="1", trace_id=trace)
    decide(admin_client(), approval_id)
    approval_token = poll(approval_id, token).json()["approval_token"]
    call("purge_reports", {"keep_latest": "1"}, token=token, trace_id=trace, approval_id=approval_id, approval_token=approval_token)
    seen = [(e.actor_type, e.action, e.decision) for e in audit_log.by_trace(trace) if e.action in ("purge_reports", "decide_approval")]
    assert ("agent", "purge_reports", "deny") in seen       # held
    assert ("human", "decide_approval", "allow") in seen    # approved
    assert ("agent", "purge_reports", "allow") in seen      # run
    body = admin_client().get(f"/approvals/{approval_id}/trace").json()
    assert body["trace_id"] == trace and len(body["events"]) >= 3


def test_nonsense_arguments_are_refused_before_anyone_is_asked_to_approve(idp):
    before = conn.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()["n"]
    res = call("purge_reports", {"keep_latest": "all of them"}, token=agent_token(idp))
    assert res.status_code == 400
    assert conn.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()["n"] == before


def test_an_agent_without_the_purge_scope_never_reaches_the_queue(idp):
    res = call("purge_reports", {"keep_latest": "1"}, token=agent_token(idp, "stats:read reports:write"))
    assert res.status_code == 403 and "tool-not-granted" in res.json()["detail"]


def test_only_the_agent_that_asked_can_poll_its_request(client, idp):
    _, approval_id = ask_to_purge(idp)
    assert poll(approval_id, "not-a-token").status_code == 401
    assert client.get(f"/agent/approvals/{approval_id}").status_code == 401


# --- the policy says which calls need a person --------------------------------------

def test_an_answer_that_does_not_mention_approval_is_treated_as_needing_it():
    d = opa_client.decision_from_opa({"result": {"allow": True, "policies": ["p"], "reasons": ["r"]}})
    assert d.allow and d.requires_approval


def test_only_an_explicit_false_skips_the_approval():
    d = opa_client.decision_from_opa({"result": {"allow": True, "policies": [], "reasons": [], "requires_approval": False}})
    assert d.allow and not d.requires_approval


def test_the_token_carries_the_approval_marker_on_the_purge_capability(idp):
    claims = idp.post("/introspect", data={"token": agent_token(idp)}, auth=("lab-resource-server", "lab-resource-server-secret-do-not-reuse")).json()
    purge = next(c for c in claims["capabilities"] if c["tool"] == "purge_reports")
    assert purge["approval"] == "required"
    assert all("approval" not in c for c in claims["capabilities"] if c["tool"] != "purge_reports")


def test_ordinary_tools_do_not_wait_for_anyone(idp):
    assert call("get_stats", token=agent_token(idp)).status_code == 200


# --- the runner waits like a patient client ------------------------------------------

class Router:
    def __init__(self, idp, api):
        self._idp, self._api = idp, api

    def request(self, method, url, **kw):
        return (self._idp if url.startswith(IDP_URL) else self._api).request(method, url, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def newest_pending():
    return conn.execute("SELECT id FROM approvals WHERE status = 'pending' ORDER BY id DESC LIMIT 1").fetchone()["id"]


def test_the_runner_waits_for_a_person_then_repeats_the_call_with_the_token(idp):
    seed_reports(5)
    http, admin, noticed = Router(idp, TestClient(app)), admin_client(), []

    def person_decides(_):
        decide(admin, newest_pending())

    tokens = TokenManager(http, IDP_URL, *AGENT, SCOPE)
    history, offered = run_once(
        TidyUpAgent(), tokens, http, API,
        approval_wait=ApprovalWait(sleep=person_decides, on_pending=lambda i, t: noticed.append((i, t))),
    )
    assert [o.ok for o in history] == [True, True, True], [o.error for o in history]
    assert noticed and noticed[0][1] == "purge_reports"
    assert history[1].result["kept"] == 2 and report_count() >= 2
    assert "purge_reports" in [t.name for t in offered]


def test_the_runner_reports_a_denial_and_stops(idp):
    seed_reports()
    http, admin = Router(idp, TestClient(app)), admin_client()
    tokens = TokenManager(http, IDP_URL, *AGENT, SCOPE)
    before = report_count()
    history, _ = run_once(
        TidyUpAgent(), tokens, http, API,
        approval_wait=ApprovalWait(sleep=lambda _: decide(admin, newest_pending(), "deny", "no")),
    )
    assert [o.ok for o in history] == [True, False]
    assert "denied" in history[1].error and report_count() == before


def test_the_runner_gives_up_when_nobody_answers(idp):
    http = Router(idp, TestClient(app))
    tokens = TokenManager(http, IDP_URL, *AGENT, SCOPE)
    ticks = iter(range(100))
    history, _ = run_once(
        TidyUpAgent(), tokens, http, API,
        approval_wait=ApprovalWait(timeout=3, sleep=lambda _: None, clock=lambda: next(ticks)),
    )
    assert not history[1].ok and "timeout" in history[1].error


def test_a_runner_that_is_not_set_up_to_wait_says_so_instead_of_hanging(idp):
    http = Router(idp, TestClient(app))
    tokens = TokenManager(http, IDP_URL, *AGENT, SCOPE)
    history, _ = run_once(TidyUpAgent(), tokens, http, API)
    assert not history[1].ok and "approval" in history[1].error


def test_the_scripted_agent_is_not_offered_the_purge_tool_by_default(idp):
    tokens = TokenManager(idp, IDP_URL, *AGENT, "stats:read reports:write")
    history, offered = run_once(ScriptedAgent(), tokens, TestClient(app), API)
    assert "purge_reports" not in [t.name for t in offered] and all(o.ok for o in history)
