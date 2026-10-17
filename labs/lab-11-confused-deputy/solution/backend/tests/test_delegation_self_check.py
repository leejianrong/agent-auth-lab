"""Self-check suite for lab 09: acting on behalf of a person.

    pytest tests/test_delegation_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 09
handout. The three groups map to the three tasks:

  1. Composing a token that names the person and the agent  (idp/lab_idp/oauth.py: compose_delegated_claims)
  2. Narrowing a delegated token's scopes                    (idp/lab_idp/oauth.py: narrow_delegated_scope)
  3. Accepting only delegated tokens downstream              (app/oidc_client.py: delegated_token_allowed)
"""

import pytest
from fastapi.testclient import TestClient

from agent_runner.agent import NotesSummaryAgent
from agent_runner.auth import TokenManager
from agent_runner.delegation import TOKEN_EXCHANGE
from agent_runner.runner import do_next_task, run_once
from app import oidc_client
from app.main import app, audit_log, conn, delegation_chain
from helpers import ensure_opa, full_login
from lab_idp import oauth

AGENT = ("tidy-agent", "tidy-agent-secret-do-not-reuse")
RS = ("lab-resource-server", "lab-resource-server-secret-do-not-reuse")
IDP_URL, API = "http://localhost:9000", "http://localhost:8000"


@pytest.fixture(autouse=True)
def _opa():
    ensure_opa()


class Router:
    """Stands in for one httpx client that can reach both the IdP and the app."""

    def __init__(self, idp, api):
        self._idp, self._api = idp, api

    def request(self, method, url, **kw):
        return (self._idp if url.startswith(IDP_URL) else self._api).request(method, url, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def person_session(idp, username="alice", password=None, approve=None):
    client = TestClient(app, follow_redirects=False)
    full_login(client, idp, username=username, password=password or f"{username}-lab-pass", approve=approve)
    return client


def ask(client):
    res = client.post("/agent/tasks", json={})
    assert res.status_code == 201, res.text
    task = conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (res.json()["id"],)).fetchone()
    return res.json(), task["subject_token"]


def exchange(idp, subject_token, scope="notes:read", auth=AGENT, headers=None):
    return idp.post("/token", data={"grant_type": TOKEN_EXCHANGE, "subject_token": subject_token, "scope": scope},
                    auth=auth, headers=headers or {})


def introspect(idp, token):
    return idp.post("/introspect", data={"token": token}, auth=RS).json()


def delegated_token(idp, username="alice", approve=None):
    _, subject = ask(person_session(idp, username, approve=approve))
    res = exchange(idp, subject)
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def get_notes(token):
    return TestClient(app).get("/delegated/notes", headers={"Authorization": f"Bearer {token}"})


def events(action):
    return [e for e in audit_log.recent(200) if e.action == action]


# --- task 1: a token that names the person and the agent -----------------------

SUBJECT = {"active": True, "sub": "idp-alice", "client_id": "lab-client", "scope": "openid notes:read", "exp": 5000, "iat": 1000}


def claims(**kw):
    args = dict(agent_id="tidy-agent", agent_name="Tidy agent", sponsor="idp-bob", scope="notes:read",
                issuer="http://localhost:9000", now=1000, ttl=120)
    return oauth.compose_delegated_claims({**SUBJECT, **kw.pop("subject", {})}, **{**args, **kw})


def test_the_delegated_token_keeps_the_persons_sub():
    assert claims()["sub"] == "idp-alice"


def test_the_delegated_token_says_which_agent_is_acting():
    c = claims()
    assert c["acting_as"] == {"sub": "tidy-agent", "sponsor": "idp-bob"}
    assert c["client_id"] == "tidy-agent" and c["client_type"] == "agent"


def test_the_delegated_token_never_outlives_the_persons_token():
    assert claims()["exp"] == 1120
    assert claims(subject={"exp": 1050})["exp"] == 1050


def test_the_delegated_token_carries_the_usual_claims_and_no_capabilities():
    c = claims()
    assert c["scope"] == "notes:read" and c["iss"] == "http://localhost:9000" and c["aud"] == "http://localhost:9000"
    assert c["iat"] == 1000 and c["jti"] and c["sponsor"] == "idp-bob" and c["client_name"] == "Tidy agent"
    assert "capabilities" not in c


# --- task 2: only scopes the person holds and the agent may be given -----------

def test_a_delegated_scope_must_be_requested_held_and_delegable():
    assert oauth.narrow_delegated_scope({"notes:read", "openid"}, {"notes:read"}, {"notes:read"}) == {"notes:read"}


def test_the_agent_cannot_be_given_a_scope_the_person_does_not_hold():
    assert oauth.narrow_delegated_scope({"openid", "profile"}, {"notes:read"}, {"notes:read"}) == set()


def test_the_agent_cannot_be_given_a_scope_it_is_not_trusted_with():
    assert oauth.narrow_delegated_scope({"notes:read", "notes:write"}, {"notes:read", "notes:write"}, {"notes:read"}) == {"notes:read"}


def test_asking_for_nothing_gets_nothing():
    assert oauth.narrow_delegated_scope({"notes:read"}, set(), {"notes:read"}) == set()


def test_a_person_who_withheld_notes_read_at_consent_cannot_be_delegated_it(idp):
    client = person_session(idp, "carol", approve=["profile"])
    _, subject = ask(client)
    res = exchange(idp, subject)
    assert res.status_code == 400 and res.json()["error"] == "invalid_scope"
    assert audit_idp(idp, "token_exchange")[0]["decision"] == "deny"


def audit_idp(idp, action):
    return [e for e in idp.get("/observability/events", params={"limit": 200}).json() if e["action"] == action]


# --- task 3: downstream APIs accept only delegated tokens ----------------------

DELEGATED = {"active": True, "sub": "idp-alice", "client_id": "tidy-agent", "client_type": "agent", "scope": "notes:read",
             "acting_as": {"sub": "tidy-agent", "sponsor": "idp-bob"}}


def allowed(result, scope="notes:read"):
    return oidc_client.delegated_token_allowed(result, scope)


def test_a_delegated_token_with_the_scope_is_accepted():
    assert allowed(DELEGATED)[0] is True


def test_an_inactive_token_is_refused_first():
    ok, reason = allowed({"active": False})
    assert ok is False and "not active" in reason


def test_a_persons_own_token_is_refused_because_no_agent_is_in_the_chain():
    ok, reason = allowed({"active": True, "sub": "idp-alice", "client_id": "lab-client", "scope": "notes:read"})
    assert ok is False and "not delegated" in reason


def test_an_agents_own_token_is_refused_because_no_person_is_in_the_chain():
    own = {"active": True, "sub": "tidy-agent", "client_id": "tidy-agent", "client_type": "agent", "scope": "notes:read"}
    ok, reason = allowed(own)
    assert ok is False and "not delegated" in reason
    ok, reason = allowed({**own, "acting_as": {"sub": "tidy-agent"}})
    assert ok is False and "no person" in reason


def test_a_delegated_token_without_the_scope_is_refused():
    ok, reason = allowed({**DELEGATED, "scope": "profile"})
    assert ok is False and "insufficient_scope" in reason


# --- the exchange at the IdP -----------------------------------------------------

def test_the_exchanged_token_names_alice_and_the_agent(idp):
    token = delegated_token(idp)
    result = introspect(idp, token)
    assert result["active"] and result["sub"] == "idp-alice" and result["scope"] == "notes:read"
    assert result["acting_as"]["sub"] == "tidy-agent" and result["sponsor"] == "idp-alice"
    assert not result.get("capabilities")


def test_the_exchange_is_audited_at_the_idp_with_both_identities(idp):
    delegated_token(idp)
    ev = audit_idp(idp, "token_exchange")[0]
    assert ev["decision"] == "allow" and ev["actor_id"] == "tidy-agent" and ev["metadata"]["on_behalf_of"] == "idp-alice"


def test_the_wrong_agent_secret_is_refused(idp):
    _, subject = ask(person_session(idp))
    assert exchange(idp, subject, auth=("tidy-agent", "wrong")).status_code == 401


def test_a_service_that_is_not_registered_for_delegation_is_refused(idp):
    _, subject = ask(person_session(idp))
    res = exchange(idp, subject, auth=("digest-service", "digest-service-secret-do-not-reuse"))
    assert res.status_code == 401


def test_a_service_token_is_not_a_persons_token(idp):
    svc = idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"},
                   auth=("digest-service", "digest-service-secret-do-not-reuse")).json()["access_token"]
    assert exchange(idp, svc).status_code == 400


def test_a_delegated_token_cannot_be_delegated_again(idp):
    assert exchange(idp, delegated_token(idp)).status_code == 400


def test_a_revoked_persons_token_cannot_be_exchanged(idp):
    _, subject = ask(person_session(idp))
    idp.post("/revoke", data={"token": subject, "client_id": "lab-client"})
    assert exchange(idp, subject).status_code == 400


def test_the_delegated_token_expires_no_later_than_the_persons_token(idp):
    _, subject = ask(person_session(idp))
    persons = introspect(idp, subject)
    res = exchange(idp, subject).json()
    assert introspect(idp, res["access_token"])["exp"] <= persons["exp"]


# --- the downstream API ------------------------------------------------------------

def test_the_downstream_api_returns_the_notes_of_the_person_not_the_agent(idp):
    alice = person_session(idp)
    alice.post("/notes", json={"title": "alice-only note", "body": "b"})
    res = get_notes(delegated_token(idp))
    assert res.status_code == 200 and res.json()["on_behalf_of"] == "idp-alice"
    assert "alice-only note" in [n["title"] for n in res.json()["notes"]]


def test_the_downstream_audit_log_has_the_persons_sub_distinct_from_the_agents(idp):
    get_notes(delegated_token(idp))
    ev = events("read_notes")[0]
    assert ev.actor_type == "agent" and ev.actor_id == "tidy-agent" and ev.decision == "allow"
    assert ev.metadata["on_behalf_of"] == "idp-alice" and ev.metadata["sponsor"] == "idp-alice"


def test_an_agents_own_token_is_refused_downstream(idp):
    own = idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"}, auth=AGENT).json()["access_token"]
    res = get_notes(own)
    assert res.status_code == 403 and "not delegated" in res.json()["detail"]


def test_a_persons_own_token_is_refused_downstream(idp):
    _, subject = ask(person_session(idp))
    assert get_notes(subject).status_code == 403


def test_a_delegated_token_is_not_a_service_token(idp):
    token = delegated_token(idp)
    res = TestClient(app).get("/internal/stats", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)


def test_a_delegated_token_does_not_open_the_tool_gateway(idp):
    token = delegated_token(idp)
    res = TestClient(app).post("/agent/tools/get_stats", json={"args": {}}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403 and "tool-not-granted" in res.json()["detail"]


# --- tasks -------------------------------------------------------------------------

def test_only_a_session_from_the_lab_idp_can_hand_the_agent_a_task(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "pw-" + new_username})
    client.post("/login", json={"username": new_username, "password": "pw-" + new_username})
    assert client.post("/agent/tasks", json={}).status_code == 400


def test_a_task_needs_a_session():
    assert TestClient(app).post("/agent/tasks", json={}).status_code == 401


def test_only_an_agent_acting_as_itself_may_claim_tasks(idp):
    assert TestClient(app).get("/agent/tasks/next").status_code == 401
    token = delegated_token(idp)
    res = TestClient(app).get("/agent/tasks/next", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_completing_a_task_discards_the_persons_token(idp):
    ticket, _ = ask(person_session(idp))
    tokens = TokenManager(idp, IDP_URL, *AGENT, "stats:read reports:write")
    auth = {"Authorization": f"Bearer {tokens.get('a' * 32)}"}
    api = TestClient(app)
    while (task := api.get("/agent/tasks/next", headers=auth).json()["task"]) and task["id"] != ticket["id"]:
        pass
    assert task and task["subject_token"]
    assert api.post(f"/agent/tasks/{task['id']}/complete", headers=auth).status_code == 200
    row = conn.execute("SELECT * FROM agent_tasks WHERE id = ?", (task["id"],)).fetchone()
    assert row["status"] == "done" and row["subject_token"] is None


def test_an_agent_cannot_complete_a_task_it_never_claimed(idp):
    ticket, _ = ask(person_session(idp))
    tokens = TokenManager(idp, IDP_URL, *AGENT, "stats:read reports:write")
    res = TestClient(app).post(f"/agent/tasks/{ticket['id']}/complete", headers={"Authorization": f"Bearer {tokens.get('b' * 32)}"})
    assert res.status_code == 404


# --- the whole chain, end to end -----------------------------------------------------

def run_task(idp):
    alice = person_session(idp)
    alice.post("/notes", json={"title": "chain note", "body": "b"})
    ticket, _ = ask(alice)
    http = Router(idp, TestClient(app))
    tokens = TokenManager(http, IDP_URL, *AGENT, "stats:read reports:write")
    # earlier tests may have left tasks pending: work through them until ours is done
    while True:
        task, history, offered = do_next_task(NotesSummaryAgent(), tokens, http, IDP_URL, API, *AGENT)
        if task is None or task["id"] == ticket["id"]:
            return alice, ticket, task, history, offered


def test_the_scripted_agent_reads_alices_notes_then_reports_with_its_own_token(idp):
    _, _, task, history, offered = run_task(idp)
    assert task and [o.ok for o in history] == [True, True]
    assert [o.action.tool for o in history] == ["read_notes", "write_report"]
    assert "read_notes" in [t.name for t in offered]


def test_read_notes_is_not_offered_to_an_agent_that_is_not_acting_for_anyone(idp):
    tokens = TokenManager(idp, IDP_URL, *AGENT, "stats:read reports:write")
    _, offered = run_once(NotesSummaryAgent(), tokens, TestClient(app), API)
    assert "read_notes" not in [t.name for t in offered]


def test_an_agent_that_tries_downstream_with_its_own_token_is_refused(idp):
    tokens = TokenManager(idp, IDP_URL, *AGENT, "stats:read reports:write")
    history, _ = run_once(NotesSummaryAgent(), tokens, TestClient(app), API, enforce_offer=False)
    assert history[0].ok is False and "not delegated" in history[0].error


def test_the_trace_shows_the_person_the_agent_and_the_api(idp):
    alice, ticket, _, _, _ = run_task(idp)
    trace = alice.get(f"/delegation/trace/{ticket['trace_id']}").json()
    assert [(h["role"], h["id"]) for h in trace["chain"]] == [
        ("human", "idp-alice"), ("agent", "tidy-agent"), ("api", "/delegated/notes"),
    ]
    assert trace["status"] == "done"
    assert {e["source"] for e in trace["events"]} == {"app", "idp"}
    actions = [e["action"] for e in trace["events"]]
    assert actions.index("create_agent_task") < actions.index("token_exchange") < actions.index("read_notes")


def test_the_whole_chain_shares_one_trace_id(idp):
    alice, ticket, _, _, _ = run_task(idp)
    trace = alice.get(f"/delegation/trace/{ticket['trace_id']}").json()
    assert all(e["trace_id"] == ticket["trace_id"] for e in trace["events"])
    reads = [e for e in trace["events"] if e["action"] == "read_notes"]
    assert reads and reads[0]["metadata"]["on_behalf_of"] == "idp-alice"


def test_only_the_person_who_asked_and_admins_can_read_the_trace(idp):
    alice, ticket, _, _, _ = run_task(idp)
    bob = person_session(idp, "bob")
    assert bob.get(f"/delegation/trace/{ticket['trace_id']}").status_code == 404
    admin = TestClient(app, follow_redirects=False)
    admin.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"})
    assert admin.get(f"/delegation/trace/{ticket['trace_id']}").status_code == 200


def test_the_chain_reader_orders_hops_and_ignores_unrelated_events():
    evs = [
        {"action": "create_agent_task", "actor_type": "human", "actor_id": "idp-alice", "decision": "allow", "resource": "task:1", "metadata": {}},
        {"action": "x", "actor_type": "service", "actor_id": "other", "decision": "allow", "resource": None, "metadata": {}},
        {"action": "read_notes", "actor_type": "agent", "actor_id": "tidy-agent", "decision": "deny", "resource": "/delegated/notes",
         "metadata": {"on_behalf_of": "idp-alice", "sponsor": "idp-bob"}},
    ]
    assert [h["role"] for h in delegation_chain(evs)] == ["human", "agent"]
