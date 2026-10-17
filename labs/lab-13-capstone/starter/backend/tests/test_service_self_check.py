"""Self-check suite for lab 06: service-to-service authentication.

    pytest tests/test_service_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 06
handout, made executable. The three groups map to the three tasks:

  1. Authenticating the service client   (idp/lab_idp/oauth.py: authenticate_client)
  2. Narrowing what it may hold          (idp/lab_idp/oauth.py: scopes_for_service)
  3. Accepting only service tokens       (app/oidc_client.py: service_token_allowed)
"""

import base64

import pytest
from fastapi.testclient import TestClient

from app import oidc_client
from app.main import app, audit_log
from digest_service.client import DigestError, run_digest
from helpers import full_login

GOOD = ("digest-service", "digest-service-secret-do-not-reuse")


def token_request(idp, auth=GOOD, scope="stats:read", **extra):
    return idp.post("/token", data={"grant_type": "client_credentials", "scope": scope, **extra}, auth=auth)


def good_token(idp, scope="stats:read"):
    return token_request(idp, scope=scope).json()["access_token"]


def stats(client, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get("/internal/stats", headers=headers)


# --- task 1: authenticate the service client ----------------------------------

def test_authenticate_client_accepts_the_real_secret(idp_module):
    assert idp_module.oauth.authenticate_client(*GOOD) is True


def test_authenticate_client_rejects_a_wrong_secret(idp_module):
    assert idp_module.oauth.authenticate_client("digest-service", "wrong") is False
    assert idp_module.oauth.authenticate_client("digest-service", "") is False


def test_authenticate_client_rejects_an_unknown_client(idp_module):
    assert idp_module.oauth.authenticate_client("nobody", GOOD[1]) is False


def test_token_endpoint_refuses_a_wrong_secret_with_401(idp):
    res = token_request(idp, auth=("digest-service", "wrong"))
    assert res.status_code == 401 and res.json() == {"error": "invalid_client"}


def test_token_endpoint_refuses_a_known_client_id_with_no_secret(idp):
    res = idp.post("/token", data={"grant_type": "client_credentials", "client_id": "digest-service", "scope": "stats:read"})
    assert res.status_code == 401


def test_a_refused_client_is_audited_as_a_deny(idp):
    trace = "ab" * 16
    idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read"},
             auth=("digest-service", "wrong"), headers={"X-Trace-Id": trace})
    events = idp.get(f"/observability/traces/{trace}").json()
    assert any(e["action"] == "oidc_client_auth" and e["decision"] == "deny" for e in events)


def test_the_real_secret_gets_a_token_with_no_user_in_it(idp):
    body = token_request(idp).json()
    assert body["scope"] == "stats:read" and body["token_type"] == "Bearer"
    result = idp.post("/introspect", data={"token": body["access_token"]},
                      auth=("lab-resource-server", "lab-resource-server-secret-do-not-reuse")).json()
    assert result["sub"] == result["client_id"] == "digest-service"


# --- task 2: narrow the scopes ------------------------------------------------

def test_scopes_for_service_keeps_only_registered_scopes(idp_module):
    got = idp_module.oauth.scopes_for_service("digest-service", {"stats:read", "notes:write", "admin"})
    assert got == {"stats:read"}


def test_scopes_for_service_never_adds_scopes(idp_module):
    assert idp_module.oauth.scopes_for_service("digest-service", set()) == set()


def test_a_service_asking_for_extra_scopes_gets_only_its_own(idp):
    body = token_request(idp, scope="stats:read notes:write").json()
    assert body["scope"] == "stats:read"


def test_asking_only_for_scopes_it_may_not_hold_is_refused(idp):
    res = token_request(idp, scope="notes:write")
    assert res.status_code == 400 and res.json() == {"error": "invalid_scope"}


def test_withheld_scopes_are_audited(idp):
    trace = "cd" * 16
    idp.post("/token", data={"grant_type": "client_credentials", "scope": "stats:read notes:write"},
             auth=GOOD, headers={"X-Trace-Id": trace})
    issued = [e for e in idp.get(f"/observability/traces/{trace}").json() if e["action"] == "service_token_issued"]
    assert issued and issued[0]["metadata"]["withheld"] == ["notes:write"]


# --- task 3: only service tokens open service endpoints -------------------------

ACTIVE_SERVICE = {"active": True, "sub": "digest-service", "client_id": "digest-service", "scope": "stats:read"}


def test_service_token_allowed_accepts_a_proper_service_token():
    ok, _ = oidc_client.service_token_allowed(ACTIVE_SERVICE, "stats:read")
    assert ok is True


def test_service_token_allowed_rejects_an_inactive_token():
    ok, reason = oidc_client.service_token_allowed({"active": False}, "stats:read")
    assert ok is False and "not active" in reason


def test_service_token_allowed_rejects_a_token_issued_for_a_human():
    human = {"active": True, "sub": "idp-alice", "client_id": "lab-client", "scope": "openid stats:read"}
    ok, reason = oidc_client.service_token_allowed(human, "stats:read")
    assert ok is False and "user" in reason


def test_service_token_allowed_rejects_a_missing_scope():
    other = {**ACTIVE_SERVICE, "scope": "notes:read"}
    ok, reason = oidc_client.service_token_allowed(other, "stats:read")
    assert ok is False and "insufficient_scope" in reason


def test_service_token_allowed_matches_scopes_by_whole_name():
    lookalike = {**ACTIVE_SERVICE, "scope": "stats:read-all"}
    ok, _ = oidc_client.service_token_allowed(lookalike, "stats:read")
    assert ok is False


def test_the_stats_endpoint_serves_a_service_token(client, idp):
    res = stats(client, good_token(idp))
    assert res.status_code == 200 and set(res.json()) == {"users", "notes"}


def test_the_stats_endpoint_requires_a_bearer_token(client):
    assert stats(client).status_code == 401


def test_the_stats_endpoint_refuses_a_garbage_token(client):
    assert stats(client, "not-a-token").status_code == 401


def test_a_humans_access_token_cannot_open_the_stats_endpoint(client, idp, db_conn):
    """The user's token is perfectly valid at the IdP, but it was issued to a
    person and carries no `stats:read`: the service endpoint must say no."""
    full_login(client, idp)
    row = db_conn.execute(
        "SELECT s.access_token FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE u.username = 'alice@lab-idp' ORDER BY s.created_at DESC LIMIT 1").fetchone()
    res = stats(TestClient(app), row["access_token"])
    assert res.status_code == 403


def test_a_revoked_service_token_stops_working(client, idp):
    token = good_token(idp)
    assert stats(client, token).status_code == 200
    idp.post("/revoke", data={"token": token, "client_id": "digest-service"})
    assert stats(client, token).status_code == 401


def test_every_stats_decision_is_audited_with_the_service_as_actor(client, idp):
    stats(client, good_token(idp))
    stats(client, "garbage")
    calls = [e for e in audit_log.recent(100) if e.action == "service_call"]
    assert any(e.decision == "allow" and e.actor_id == "digest-service" and e.actor_type == "service" for e in calls)
    assert any(e.decision == "deny" for e in calls)


# --- the whole job, as the learner runs it ------------------------------------

def run(idp, **kw):
    return run_digest(idp_http=idp, api_http=TestClient(app), **kw)


def test_the_digest_job_completes_end_to_end(idp):
    out = run(idp)
    assert set(out["stats"]) == {"users", "notes"} and len(out["trace_id"]) == 32


def test_the_digest_job_with_a_bad_secret_fails_at_the_token_request(idp):
    with pytest.raises(DigestError) as e:
        run(idp, secret="wrong-secret")
    assert e.value.step == "token request" and "401" in e.value.detail


def test_one_trace_id_connects_the_idp_and_the_app(client, idp):
    out = run(idp)
    idp_events = idp.get(f"/observability/traces/{out['trace_id']}").json()
    app_events = [e for e in audit_log.recent(200) if e.trace_id == out["trace_id"]]
    assert any(e["action"] == "service_token_issued" for e in idp_events)
    assert any(e.action == "service_call" for e in app_events)


def admin_client():
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", json={"username": "admin", "password": "lab02-admin-do-not-reuse"}).status_code == 200
    return c


def test_the_service_calls_view_merges_both_sides_for_an_admin(idp):
    run(idp)
    with pytest.raises(DigestError):
        run(idp, secret="nope")
    rows = admin_client().get("/service-calls").json()
    sources = {r["source"] for r in rows}
    assert sources == {"app", "idp"}
    assert any(r["decision"] == "deny" and r["action"] == "oidc_client_auth" for r in rows)


def test_the_service_calls_view_is_admin_only(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "pw-" + new_username})
    client.post("/login", json={"username": new_username, "password": "pw-" + new_username})
    assert client.get("/service-calls").status_code == 403
