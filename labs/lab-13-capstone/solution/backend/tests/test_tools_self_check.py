"""Self-check suite for lab 08: capability-scoped tools, decided by OPA.

    pytest tests/test_tools_self_check.py -v

These tests start a real OPA server with this lab's `policy/` loaded (see
`ensure_opa` in helpers.py). Every test is one line of the "you're done when"
checklist in the lab 08 handout. The three groups map to the three tasks:

  1. Putting only the granted capabilities on a token  (idp/lab_idp/oauth.py: capabilities_for_scopes)
  2. Failing closed when OPA has no clear answer        (app/opa_client.py: decision_from_opa)
  3. Limiting a report's length in the policy           (policy/agent_tools.rego: report-too-long)
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_runner.agent import ProbingAgent, ScriptedAgent
from agent_runner.auth import TokenManager
from agent_runner.runner import run_once
from app import opa_client
from app.main import app, audit_log, conn
from helpers import ensure_opa
from lab_idp import oauth

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
AGENT = ("tidy-agent", "tidy-agent-secret-do-not-reuse")
API = "http://localhost:8000"


@pytest.fixture(autouse=True)
def _opa():
    ensure_opa()


def agent_token(idp, scope="stats:read reports:write"):
    res = idp.post("/token", data={"grant_type": "client_credentials", "scope": scope}, auth=AGENT)
    assert res.status_code == 200
    return res.json()["access_token"]


def call(tool, args=None, *, token, extra=None):
    body = {"args": args or {}, **(extra or {})}
    return TestClient(app).post(f"/agent/tools/{tool}", json=body, headers={"Authorization": f"Bearer {token}"})


def last_event(action):
    return next(e for e in audit_log.recent(100) if e.action == action)


def tools_of(capabilities):
    return [c["tool"] for c in capabilities]


# --- task 1: only the granted capabilities go on the token ---------------------

REGISTERED = [
    {"tool": "get_stats", "scope": "stats:read"},
    {"tool": "write_report", "scope": "reports:write", "max_body_chars": 200},
]


def test_capabilities_for_scopes_keeps_only_those_whose_scope_was_granted():
    assert tools_of(oauth.capabilities_for_scopes(REGISTERED, {"stats:read"})) == ["get_stats"]
    assert tools_of(oauth.capabilities_for_scopes(REGISTERED, {"stats:read", "reports:write"})) == ["get_stats", "write_report"]


def test_capabilities_for_scopes_gives_nothing_when_no_scope_matches():
    assert oauth.capabilities_for_scopes(REGISTERED, set()) == []
    assert oauth.capabilities_for_scopes(REGISTERED, {"notes:read"}) == []


def test_capabilities_for_scopes_keeps_the_limits_and_drops_the_scope_key():
    caps = oauth.capabilities_for_scopes(REGISTERED, {"reports:write"})
    assert caps == [{"tool": "write_report", "max_body_chars": 200}]


def test_a_token_asking_for_fewer_scopes_carries_fewer_capabilities(idp):
    result = idp.post("/introspect", data={"token": agent_token(idp, "stats:read")},
                      auth=("lab-resource-server", "lab-resource-server-secret-do-not-reuse")).json()
    assert result["scope"] == "stats:read"
    assert tools_of(result["capabilities"]) == ["get_stats"]


def test_a_full_token_carries_both_capabilities_with_their_limits(idp):
    result = idp.post("/introspect", data={"token": agent_token(idp)},
                      auth=("lab-resource-server", "lab-resource-server-secret-do-not-reuse")).json()
    assert tools_of(result["capabilities"]) == ["get_stats", "write_report"]
    assert result["capabilities"][1]["max_body_chars"] == 200


def test_a_service_that_is_not_an_agent_carries_no_capabilities(idp):
    token = idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"},
                     auth=("digest-service", "digest-service-secret-do-not-reuse")).json()["access_token"]
    result = idp.post("/introspect", data={"token": token},
                      auth=("lab-resource-server", "lab-resource-server-secret-do-not-reuse")).json()
    assert not result.get("capabilities")


# --- task 2: fail closed when OPA has no clear answer --------------------------

def test_no_answer_from_opa_means_deny():
    d = opa_client.decision_from_opa(None)
    assert d.allow is False and d.policies == ("policy-engine-unreachable",)


def test_an_empty_answer_from_opa_means_deny():
    d = opa_client.decision_from_opa({})
    assert d.allow is False and d.policies == ("policy-engine-no-decision",)


def test_a_malformed_result_means_deny():
    assert opa_client.decision_from_opa({"result": "allow"}).allow is False
    assert opa_client.decision_from_opa({"result": None}).allow is False


def test_only_a_true_allow_is_an_allow():
    assert opa_client.decision_from_opa({"result": {"allow": "true"}}).allow is False
    assert opa_client.decision_from_opa({"result": {"allow": 1}}).allow is False
    assert opa_client.decision_from_opa({"result": {}}).allow is False
    assert opa_client.decision_from_opa({"result": {"allow": True, "policies": ["capability-granted"]}}).allow is True


def test_a_denial_keeps_the_policies_and_reasons_that_decided_it():
    d = opa_client.decision_from_opa({"result": {"allow": False, "policies": ["a", "b"], "reasons": ["x", "y"]}})
    assert (d.allow, d.policies, d.reasons) == (False, ("a", "b"), ("x", "y"))


def test_an_unreachable_policy_engine_blocks_the_tool_call_and_the_work_is_not_done(idp):
    token = agent_token(idp)
    before = conn.execute("SELECT COUNT(*) AS n FROM agent_reports").fetchone()["n"]
    good = opa_client.OPA_URL
    opa_client.set_opa_url("http://127.0.0.1:9")   # nothing listens on the discard port
    try:
        res = call("write_report", {"title": "t", "body": "short"}, token=token)
    finally:
        opa_client.set_opa_url(good)
    assert res.status_code == 403 and "policy-engine-unreachable" in res.json()["detail"]
    assert conn.execute("SELECT COUNT(*) AS n FROM agent_reports").fetchone()["n"] == before


# --- task 3: the policy limits a report's length -------------------------------

def test_the_policy_files_own_unit_tests_pass():
    binary = shutil.which("opa") or __import__("os").environ.get("OPA_BIN")
    out = subprocess.run([binary, "test", str(POLICY_DIR)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def decide_directly(tool, args, capabilities=None, sponsor="idp-alice"):
    caps = [{"tool": "get_stats"}, {"tool": "write_report", "max_body_chars": 200}] if capabilities is None else capabilities
    return opa_client.decide({"agent": {"id": "tidy-agent", "sponsor": sponsor}, "capabilities": caps,
                              "tool": {"name": tool, "args": args}})


def test_opa_denies_a_report_over_the_limit_and_names_the_policy():
    d = decide_directly("write_report", {"title": "t", "body": "x" * 201})
    assert d.allow is False and d.policies == ("report-too-long",)
    assert "201" in d.summary and "200" in d.summary


def test_opa_allows_a_report_exactly_at_the_limit():
    assert decide_directly("write_report", {"title": "t", "body": "x" * 200}).allow is True


def test_the_limit_comes_from_the_capability_not_from_the_policy_file():
    caps = [{"tool": "write_report", "max_body_chars": 20}]
    assert decide_directly("write_report", {"title": "t", "body": "x" * 21}, caps).allow is False
    assert decide_directly("write_report", {"title": "t", "body": "x" * 20}, caps).allow is True


def test_a_report_over_the_limit_is_refused_by_the_gateway_and_audited_with_the_policy(idp):
    res = call("write_report", {"title": "long", "body": "y" * 500}, token=agent_token(idp))
    assert res.status_code == 403 and "report-too-long" in res.json()["detail"]
    ev = last_event("write_report")
    assert ev.decision == "deny" and ev.metadata["policies"] == ["report-too-long"]
    assert ev.actor_type == "agent" and ev.metadata["sponsor"] == "idp-alice"
    assert not conn.execute("SELECT 1 FROM agent_reports WHERE title = 'long'").fetchone()


# --- the gateway and the policy together ----------------------------------------

def test_a_granted_tool_call_is_allowed_and_the_audit_names_the_policy(idp):
    res = call("get_stats", token=agent_token(idp))
    assert res.status_code == 200 and set(res.json()) == {"users", "notes"}
    ev = last_event("get_stats")
    assert ev.decision == "allow" and ev.metadata["policies"] == ["capability-granted"] and ev.metadata["engine"] == "opa"


def test_a_short_report_is_written_and_attributed_to_the_agent(idp):
    res = call("write_report", {"title": "short one", "body": "all quiet"}, token=agent_token(idp))
    assert res.status_code == 200
    row = conn.execute("SELECT * FROM agent_reports WHERE title = 'short one'").fetchone()
    assert row["agent_id"] == "tidy-agent"


def test_a_tool_with_no_capability_is_denied_and_never_runs(idp):
    res = call("list_users", token=agent_token(idp))
    assert res.status_code == 403 and "tool-not-granted" in res.json()["detail"]
    ev = last_event("list_users")
    assert ev.decision == "deny" and ev.metadata["policies"] == ["tool-not-granted"]


def test_a_token_with_a_narrower_scope_cannot_use_the_tool_it_gave_up(idp):
    token = agent_token(idp, "stats:read")
    assert call("get_stats", token=token).status_code == 200
    res = call("write_report", {"title": "nope", "body": "b"}, token=token)
    assert res.status_code == 403 and "tool-not-granted" in res.json()["detail"]


def test_capabilities_are_read_from_the_token_never_from_the_request(idp):
    token = agent_token(idp, "stats:read")
    forged = [{"tool": "write_report", "max_body_chars": 10_000}]
    res = call("write_report", {"title": "forged", "body": "b"}, token=token, extra={"capabilities": forged})
    assert res.status_code == 403


def test_an_unknown_tool_is_not_found(idp):
    assert call("format_disk", token=agent_token(idp)).status_code == 404


def test_the_gateway_needs_a_token():
    assert TestClient(app).post("/agent/tools/get_stats", json={"args": {}}).status_code == 401


def test_a_service_that_is_not_an_agent_cannot_use_the_gateway(idp):
    token = idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"},
                     auth=("digest-service", "digest-service-secret-do-not-reuse")).json()["access_token"]
    res = call("get_stats", token=token)
    assert res.status_code == 403 and "only an agent" in res.json()["detail"]


def test_a_probing_agent_that_skips_the_runners_checks_is_stopped_by_the_policy(idp):
    tokens = TokenManager(idp, "http://localhost:9000", *AGENT, "stats:read reports:write")
    history, offered = run_once(ProbingAgent(), tokens, TestClient(app), API, enforce_offer=False)
    assert [o.ok for o in history] == [True, False, False]
    assert "report-too-long" in history[1].error and "tool-not-granted" in history[2].error
    assert "list_users" not in [t.name for t in offered]


def test_the_scripted_agent_still_works_end_to_end_through_the_gateway(idp):
    tokens = TokenManager(idp, "http://localhost:9000", *AGENT, "stats:read reports:write")
    history, _ = run_once(ScriptedAgent(), tokens, TestClient(app), API)
    assert [o.ok for o in history] == [True, True]


def test_the_agent_dashboard_data_carries_the_denying_policy(idp):
    call("list_users", token=agent_token(idp))
    c = TestClient(app, follow_redirects=False)
    c.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"})
    events = c.get("/agent-activity").json()["events"]
    denied = [e for e in events if e["decision"] == "deny" and e["action"] == "list_users"]
    assert denied and denied[0]["metadata"]["policies"] == ["tool-not-granted"]
