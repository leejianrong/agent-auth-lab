"""Self-check suite for lab 05: consent, introspection and revocation.

    pytest tests/test_consent_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 05
handout, made executable. The three groups map to the three tasks:

  1. Granting only what the user approved   (idp/lab_idp/oauth.py: granted_scopes)
  2. Honouring revocation                   (idp/lab_idp/oauth.py: is_revoked)
  3. Checking scopes by whole name          (app/oidc_client.py: has_scope)
"""

import time

import jwt
import pytest

from app import oidc_client
from helpers import callback, full_login, idp_sign_in, query, start_login

ALL = ["openid", "profile", "notes:read", "notes:write"]
RS_AUTH = ("lab-resource-server", "lab-resource-server-secret-do-not-reuse")


@pytest.fixture()
def forget_consent(idp_module):
    """Start a test as if the user had never agreed to anything."""
    def forget(sub):
        idp_module.conn.execute("DELETE FROM consents WHERE sub = ?", (sub,))
        idp_module.conn.commit()
    return forget


def access_token_of(db_conn, username):
    row = db_conn.execute(
        "SELECT s.access_token FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE u.username = ? ORDER BY s.created_at DESC LIMIT 1", (username,),
    ).fetchone()
    return row["access_token"]


def introspect(idp, token, auth=RS_AUTH):
    return idp.post("/introspect", data={"token": token}, auth=auth)


# --- task 1: grant only what the user approved --------------------------------

def test_granted_scopes_keeps_only_approved_requested_scopes(idp_module):
    got = idp_module.oauth.granted_scopes({"openid", "profile", "notes:read", "notes:write"}, {"profile", "notes:read"})
    assert got == {"openid", "profile", "notes:read"}


def test_granted_scopes_always_keeps_openid_when_requested(idp_module):
    assert idp_module.oauth.granted_scopes({"openid", "notes:read"}, set()) == {"openid"}


def test_granted_scopes_ignores_scopes_the_idp_has_never_heard_of(idp_module):
    got = idp_module.oauth.granted_scopes({"openid", "admin:everything"}, {"openid", "admin:everything"})
    assert got == {"openid"}


def test_granted_scopes_never_grants_what_was_not_requested(idp_module):
    assert idp_module.oauth.granted_scopes({"openid"}, {"openid", "notes:write"}) == {"openid"}


def test_an_unticked_scope_is_missing_from_the_access_token(client, idp, db_conn, forget_consent):
    forget_consent("idp-bob")
    full_login(client, idp, username="bob", password="bob-lab-pass", approve=["profile", "notes:read"])
    token = access_token_of(db_conn, "bob@lab-idp")
    result = introspect(idp, token).json()
    assert result["active"] is True
    assert sorted(result["scope"].split()) == ["notes:read", "openid", "profile"]


def test_the_consent_decision_is_audited_with_what_was_withheld(client, idp, forget_consent):
    forget_consent("idp-bob")
    authorize_url, _, _ = full_login(client, idp, username="bob", password="bob-lab-pass", approve=["notes:read"])
    trace = idp.get(f"/observability/traces/{query(authorize_url)['trace_id']}").json()
    consent = [e for e in trace if e["action"] == "oidc_consent" and e["decision"] == "allow"]
    assert consent and "notes:write" in consent[0]["metadata"]["withheld"]


def test_a_user_can_deny_the_whole_request(client, idp, forget_consent):
    forget_consent("idp-bob")
    authorize_url = start_login(client)
    res = idp_sign_in(idp, authorize_url, username="bob", password="bob-lab-pass", decision="deny")
    assert res.status_code == 302 and "error=access_denied" in res.headers["location"]
    assert "code=" not in res.headers["location"]


def test_consent_is_asked_once_and_remembered(client, idp, forget_consent):
    forget_consent("idp-carol")
    first = start_login(client)
    idp_sign_in(idp, first, username="carol", password="carol-lab-pass")
    # Second login: the IdP already holds a consent covering every requested scope.
    second = start_login(client)
    params = query(second)
    page = idp.post(f"/authorize/login?trace_id={params['trace_id']}",
                    data={**params, "username": "carol", "password": "carol-lab-pass"})
    assert page.status_code == 302 and "code=" in page.headers["location"]


def test_asking_for_a_new_scope_asks_again(idp, idp_module, forget_consent):
    """Incremental consent: agreeing to less earlier doesn't cover a bigger request."""
    forget_consent("idp-carol")
    idp_module.conn.execute(
        "INSERT INTO consents (sub, client_id, scopes, granted_at) VALUES ('idp-carol', 'lab-client', 'openid profile', ?)",
        (time.time(),),
    )
    idp_module.conn.commit()
    params = {
        "client_id": "lab-client", "redirect_uri": "http://localhost:8000/auth/oidc/callback", "response_type": "code",
        "state": "s", "nonce": "n", "scope": "openid profile notes:read", "code_challenge": "x" * 43,
        "code_challenge_method": "S256", "trace_id": "",
    }
    res = idp.post("/authorize/login", data={**params, "username": "carol", "password": "carol-lab-pass"})
    assert res.status_code == 200 and "Allow access?" in res.text
    assert "notes:read" in res.text and "new" in res.text


def test_needs_consent_only_when_something_new_is_requested(idp_module):
    needs = idp_module.oauth.needs_consent
    assert needs({"openid"}, {"openid", "notes:read"}) is True
    assert needs({"openid", "notes:read"}, {"openid", "notes:read"}) is False
    assert needs({"openid", "notes:read", "notes:write"}, {"openid"}) is False


# --- task 2: honour revocation -----------------------------------------------

def test_is_revoked_reports_revoked_and_unknown_tokens_correctly(idp_module):
    conn = idp_module.conn
    assert idp_module.oauth.is_revoked(conn, "never-seen") is False
    idp_module.oauth.revoke_token(conn, "revoked-jti")
    assert idp_module.oauth.is_revoked(conn, "revoked-jti") is True


def test_a_live_token_introspects_as_active_with_its_scopes(client, idp, db_conn, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    result = introspect(idp, access_token_of(db_conn, "alice@lab-idp")).json()
    assert result["active"] is True and result["sub"] == "idp-alice" and result["client_id"] == "lab-client"


def test_a_revoked_token_introspects_as_inactive(client, idp, db_conn, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    token = access_token_of(db_conn, "alice@lab-idp")
    assert idp.post("/revoke", data={"token": token, "client_id": "lab-client"}).status_code == 200
    assert introspect(idp, token).json() == {"active": False}


def test_revoking_from_the_app_ends_the_session_on_the_next_request(client, idp, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    assert client.get("/me").status_code == 200
    assert client.post("/oidc/token/revoke").json() == {"revoked": True}
    res = client.get("/me")
    assert res.status_code == 401 and "revoked" in res.json()["detail"]
    assert client.get("/me").status_code == 401  # and it stays ended


def test_the_denial_after_revocation_is_audited(client, idp, db_conn, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    client.post("/oidc/token/revoke")
    client.get("/me")
    row = db_conn.execute("SELECT id FROM users WHERE username = 'alice@lab-idp'").fetchone()
    from app.main import audit_log
    denials = [e for e in audit_log.recent(200)
               if e.actor_id == str(row["id"]) and e.decision == "deny" and "no longer active" in (e.reason or "")]
    assert denials


def test_another_client_cannot_revoke_someone_elses_token(client, idp, db_conn, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    token = access_token_of(db_conn, "alice@lab-idp")
    idp.post("/revoke", data={"token": token, "client_id": "some-other-client"})
    assert introspect(idp, token).json()["active"] is True


def test_an_expired_token_introspects_as_inactive(idp, idp_module):
    now = int(time.time())
    claims = {"iss": idp_module.ISSUER, "aud": idp_module.ISSUER, "sub": "idp-alice", "client_id": "lab-client",
              "scope": "openid", "iat": now - 3600, "exp": now - 60, "jti": "expired-jti"}
    token = jwt.encode(claims, idp_module.signing_key.private_pem, algorithm="RS256")
    assert introspect(idp, token).json() == {"active": False}


def test_introspection_requires_resource_server_credentials(idp):
    assert introspect(idp, "anything", auth=None).status_code == 401
    assert introspect(idp, "anything", auth=("lab-resource-server", "wrong")).status_code == 401
    assert introspect(idp, "anything", auth=("lab-client", "whatever")).status_code == 401


# --- task 3: check scopes by whole name --------------------------------------

def test_has_scope_matches_whole_scope_names_only():
    has = oidc_client.has_scope
    assert has("openid notes:read notes:write", "notes:write") is True
    assert has("openid notes:read", "notes:write") is False
    assert has("notes:write-all", "notes:write") is False
    assert has("xnotes:write", "notes:write") is False
    assert has("", "notes:write") is False


def test_a_user_who_withheld_notes_write_cannot_create_notes(client, idp, db_conn, forget_consent):
    forget_consent("idp-bob")
    full_login(client, idp, username="bob", password="bob-lab-pass", approve=["profile", "notes:read"])
    res = client.post("/notes", json={"title": "t", "body": "b"})
    assert res.status_code == 403 and res.json()["detail"] == "insufficient_scope"
    assert client.get("/notes/mine").status_code == 200  # notes:read was granted


def test_insufficient_scope_is_audited_with_what_was_needed_and_held(client, idp, db_conn, forget_consent):
    forget_consent("idp-bob")
    full_login(client, idp, username="bob", password="bob-lab-pass", approve=["profile", "notes:read"])
    client.post("/notes", json={"title": "t", "body": "b"})
    from app.main import audit_log
    hits = [e for e in audit_log.recent(200) if e.action == "create_note" and e.decision == "deny"]
    assert hits and "needs 'notes:write'" in hits[0].reason and "notes:read" in hits[0].reason


def test_a_user_who_approved_everything_can_use_notes(client, idp, forget_consent):
    forget_consent("idp-alice")
    full_login(client, idp)
    assert client.post("/notes", json={"title": "t", "body": "b"}).status_code == 201
    assert client.get("/notes/mine").status_code == 200


def test_password_logins_are_not_limited_by_scopes(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "pw-" + new_username})
    client.post("/login", json={"username": new_username, "password": "pw-" + new_username})
    assert client.post("/notes", json={"title": "t", "body": "b"}).status_code == 201
