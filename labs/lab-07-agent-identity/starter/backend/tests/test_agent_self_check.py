"""Self-check suite for lab 07: an agent with its own identity.

    pytest tests/test_agent_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 07
handout, made executable. The three groups map to the three tasks:

  1. Recognising an agent in the audit trail   (app/oidc_client.py: actor_from_token)
  2. Refreshing an unattended agent's token    (agent/agent_runner/auth.py: needs_new_token)
  3. Offering an agent only its own tools      (agent/agent_runner/tools.py: tools_for_scopes)
"""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent_runner.agent import Action, Observation, ScriptedAgent
from agent_runner.auth import TOKEN_REFRESH_SKEW_SECONDS, TokenManager, needs_new_token
from agent_runner.llm_agent import LlmAgent
from agent_runner.runner import run_once, run_schedule
from agent_runner.tools import TOOLS, tools_for_scopes
from app import oidc_client
from app.main import app, audit_log, conn

AGENT_SECRET = "tidy-agent-secret-do-not-reuse"


def make_tokens(idp, secret=AGENT_SECRET, clock=None):
    kw = {"clock": clock} if clock else {}
    return TokenManager(idp, "http://localhost:9000", "tidy-agent", secret, "stats:read reports:write", **kw)


def run_agent(idp, agent=None, **kw):
    return run_once(agent or ScriptedAgent(), make_tokens(idp), TestClient(app), "http://localhost:8000", **kw)


def admin_client():
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"}).status_code == 200
    return c


# --- task 1: recognise an agent in the audit trail ----------------------------

AGENT = {"active": True, "client_type": "agent", "client_id": "tidy-agent", "client_name": "Tidy agent",
         "sponsor": "idp-alice", "sub": "tidy-agent", "scope": "stats:read"}


def test_actor_from_token_recognises_an_agent_and_its_sponsor():
    actor = oidc_client.actor_from_token(AGENT)
    assert (actor.type, actor.id, actor.sponsor, actor.name) == ("agent", "tidy-agent", "idp-alice", "Tidy agent")


def test_actor_from_token_recognises_an_ordinary_service():
    svc = {"active": True, "client_type": "service", "client_id": "digest-service", "sub": "digest-service"}
    actor = oidc_client.actor_from_token(svc)
    assert (actor.type, actor.id, actor.sponsor) == ("service", "digest-service", None)


def test_actor_from_token_recognises_a_human():
    human = {"active": True, "client_id": "lab-client", "sub": "idp-alice", "scope": "openid"}
    actor = oidc_client.actor_from_token(human)
    assert (actor.type, actor.id) == ("human", "idp-alice")


def test_an_agents_actions_are_audited_as_an_agent_with_its_sponsor(idp):
    run_agent(idp)
    mine = [e for e in audit_log.recent(200) if e.actor_id == "tidy-agent"]
    assert mine and all(e.actor_type == "agent" for e in mine)
    assert all(e.metadata.get("sponsor") == "idp-alice" for e in mine)


def test_the_app_keeps_a_record_of_each_agent_it_has_seen(idp):
    run_agent(idp)
    row = conn.execute("SELECT * FROM agents WHERE client_id = 'tidy-agent'").fetchone()
    assert row["sponsor_sub"] == "idp-alice" and row["name"] == "Tidy agent"


def test_the_agent_dashboard_shows_agents_and_their_events_to_an_admin(idp):
    run_agent(idp)
    data = admin_client().get("/agent-activity").json()
    assert any(a["client_id"] == "tidy-agent" for a in data["agents"])
    assert data["events"] and all(e["actor_type"] == "agent" for e in data["events"])


def test_the_agent_dashboard_is_admin_only(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "pw-" + new_username})
    client.post("/login", json={"username": new_username, "password": "pw-" + new_username})
    assert client.get("/agent-activity").status_code == 403


# --- task 2: refresh an unattended agent's token ------------------------------

def test_needs_new_token_when_there_is_no_token():
    assert needs_new_token(None, 1000.0) is True


def test_needs_new_token_is_false_while_plenty_of_life_is_left():
    assert needs_new_token(1000.0 + 600, 1000.0) is False


def test_needs_new_token_is_true_once_the_token_has_expired():
    assert needs_new_token(1000.0, 1000.0) is True
    assert needs_new_token(1000.0, 1500.0) is True


def test_needs_new_token_refreshes_before_the_token_dies():
    expires = 2000.0
    assert needs_new_token(expires, expires - TOKEN_REFRESH_SKEW_SECONDS + 1) is True
    assert needs_new_token(expires, expires - TOKEN_REFRESH_SKEW_SECONDS - 1) is False


def test_the_token_manager_refreshes_once_the_token_nears_expiry(idp):
    now = [1000.0]
    tokens = make_tokens(idp, clock=lambda: now[0])
    first = tokens.get("a" * 32)
    assert tokens.fetches == 1
    now[0] = 1050.0   # 120s token, 70s left: no refresh
    assert tokens.get("a" * 32) == first and tokens.fetches == 1
    now[0] = 1095.0   # 25s left: inside the skew, refresh
    assert tokens.get("a" * 32) != first and tokens.fetches == 2


def test_an_unattended_schedule_reuses_one_token_across_runs(idp):
    tokens = make_tokens(idp)
    seen = []
    run_schedule(ScriptedAgent(), tokens, TestClient(app), "http://localhost:8000",
                 ticks=3, interval=0, sleep=lambda s: None, on_run=lambda n, h, o: seen.append(n))
    assert seen == [1, 2, 3] and tokens.fetches == 1


def test_a_wrong_agent_secret_never_gets_a_token(idp):
    with pytest.raises(PermissionError):
        make_tokens(idp, secret="wrong").get("b" * 32)


# --- task 3: offer an agent only its own tools --------------------------------

def names(tools):
    return [t.name for t in tools]


def test_tools_for_scopes_offers_only_tools_the_token_grants():
    assert names(tools_for_scopes(TOOLS, "stats:read reports:write")) == ["get_stats", "write_report"]
    assert names(tools_for_scopes(TOOLS, "stats:read")) == ["get_stats"]


def test_tools_for_scopes_offers_nothing_for_an_empty_grant():
    assert tools_for_scopes(TOOLS, "") == ()


def test_tools_for_scopes_matches_scopes_by_whole_name():
    assert tools_for_scopes(TOOLS, "stats:read-all xreports:write") == ()


def test_the_runner_offers_the_agent_only_what_its_token_allows(idp):
    _, offered = run_agent(idp)
    assert names(offered) == ["get_stats", "write_report"]
    assert "list_users" not in names(offered)


class Greedy:
    """An agent (think: a model) that asks for a tool it was never offered."""
    name = "greedy"

    def next_action(self, history):
        return Action("list_users") if not history else None


def test_a_tool_that_was_never_offered_is_refused_before_it_reaches_the_api(idp):
    history, _ = run_agent(idp, Greedy())
    assert history[0].ok is False and "not offered" in history[0].error
    assert not [e for e in audit_log.recent(100) if e.action == "list_users"]


# --- the agent itself -----------------------------------------------------------

def test_the_scripted_agent_reads_the_stats_then_writes_a_report(idp):
    history, _ = run_agent(idp)
    assert [o.action.tool for o in history] == ["get_stats", "write_report"]
    assert all(o.ok for o in history)


def test_the_scripted_agent_is_deterministic(idp):
    a, _ = run_agent(idp)
    b, _ = run_agent(idp)
    assert [(o.action.tool, o.action.args["title"] if "title" in o.action.args else None) for o in a] == \
           [(o.action.tool, o.action.args["title"] if "title" in o.action.args else None) for o in b]


def test_the_report_an_agent_writes_is_visible_to_an_admin(idp):
    run_agent(idp)
    reports = admin_client().get("/agent/reports").json()
    assert reports and reports[0]["agent_id"] == "tidy-agent" and "users" in reports[0]["body"]


def test_reports_are_admin_only(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "pw-" + new_username})
    client.post("/login", json={"username": new_username, "password": "pw-" + new_username})
    assert client.get("/agent/reports").status_code == 403


def test_only_an_agent_may_write_reports_even_with_the_scope(idp, idp_module, monkeypatch):
    monkeypatch.setitem(idp_module.oauth.SERVICE_CLIENTS["digest-service"], "allowed_scopes", {"stats:read", "reports:write"})
    token = idp.post("/token", data={"grant_type": "client_credentials", "scope": "reports:write"},
                     auth=("digest-service", "digest-service-secret-do-not-reuse")).json()["access_token"]
    res = TestClient(app).post("/agent/reports", json={"title": "t", "body": "b"}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403 and "only an agent" in res.json()["detail"]


def test_an_agent_cannot_use_a_humans_endpoints_with_its_token(idp):
    token = make_tokens(idp).get("c" * 32)
    res = TestClient(app).get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401  # those routes want a session cookie, which an agent doesn't have


def test_a_wrong_secret_run_is_audited_as_a_denied_client_at_the_idp(idp):
    trace = "ef" * 16
    idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"},
             auth=("tidy-agent", "wrong"), headers={"X-Trace-Id": trace})
    events = idp.get(f"/observability/traces/{trace}").json()
    assert any(e["action"] == "oidc_client_auth" and e["decision"] == "deny" for e in events)


# --- the optional model-driven agent ---------------------------------------------

def fake_model(*tool_calls):
    """A stand-in for an OpenAI-compatible client that returns canned tool calls."""
    queue = list(tool_calls)

    def create(**kwargs):
        if not queue:
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=None))])
        name, args = queue.pop(0)
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(args)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[call]))])

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_a_model_driven_agent_goes_through_the_same_identity_and_audit(idp):
    tokens = make_tokens(idp)
    tokens.get("d" * 32)
    agent = LlmAgent(tools_for_scopes(TOOLS, tokens.granted_scope),
                     client=fake_model(("get_stats", {}), ("write_report", {"title": "LLM report", "body": "hi"})), model="x")
    history, _ = run_once(agent, tokens, TestClient(app), "http://localhost:8000")
    assert [o.ok for o in history] == [True, True]
    assert any(e.actor_type == "agent" and e.action == "write_report" for e in audit_log.recent(50))


def test_a_model_only_sees_the_tools_it_is_offered(idp):
    tokens = make_tokens(idp)
    tokens.get("e" * 32)
    seen = {}
    client = fake_model()
    original = client.chat.completions.create
    client.chat.completions.create = lambda **kw: (seen.update(kw), original(**kw))[1]
    LlmAgent(tools_for_scopes(TOOLS, tokens.granted_scope), client=client, model="x").next_action([])
    assert sorted(t["function"]["name"] for t in seen["tools"]) == ["get_stats", "write_report"]


def test_a_model_that_asks_for_an_unoffered_tool_is_refused(idp):
    tokens = make_tokens(idp)
    agent = LlmAgent(tools_for_scopes(TOOLS, "stats:read reports:write"), client=fake_model(("list_users", {})), model="x")
    history, _ = run_once(agent, tokens, TestClient(app), "http://localhost:8000")
    assert history[0].ok is False and "not offered" in history[0].error
