"""Self-check suite for lab 00. Run this against your own implementation
with:

    pytest tests/test_self_check.py -v

Every test here is one line of the "you're done when" checklist in the
lab 00 handout, made executable.
"""

import time

from app import security


def test_password_hashing_round_trips():
    hashed = security.hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple", "password must not be stored as-is"
    assert security.verify_password("correct horse battery staple", hashed)
    assert not security.verify_password("wrong guess", hashed)


def test_signup_then_login_succeeds(client, new_username):
    signup = client.post("/signup", json={"username": new_username, "password": "hunter22"})
    assert signup.status_code == 201

    login = client.post("/login", json={"username": new_username, "password": "hunter22"})
    assert login.status_code == 200
    assert "session_id" in login.cookies


def test_password_stored_hashed_not_plaintext(client, db_conn, new_username):
    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    row = db_conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (new_username,)
    ).fetchone()
    assert row["password_hash"] != "hunter22"


def test_login_wrong_password_denied(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    resp = client.post("/login", json={"username": new_username, "password": "wrong"})
    assert resp.status_code == 401
    assert "session_id" not in resp.cookies


def test_me_requires_valid_session(client):
    resp = client.get("/me")
    assert resp.status_code == 401


def test_tampered_session_cookie_rejected(client):
    client.cookies.set("session_id", "not-a-real-session-id")
    resp = client.get("/me")
    assert resp.status_code == 401


def test_full_login_flow_reaches_me_and_logout(client, new_username):
    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    client.post("/login", json={"username": new_username, "password": "hunter22"})

    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["username"] == new_username

    logout = client.post("/logout")
    assert logout.status_code == 200

    after_logout = client.get("/me")
    assert after_logout.status_code == 401


def test_session_id_rotates_on_login_session_fixation(client, new_username):
    """An attacker who fixes a victim's session cookie before login must not
    be able to reuse it afterward — login has to mint a fresh session id.

    Sends the pre-existing cookie as a raw header (rather than through the
    test client's cookie jar) so this test exercises exactly what a real
    attacker-planted cookie would look like on the wire.
    """
    client.post("/signup", json={"username": new_username, "password": "hunter22"})

    pre_existing_session_id = "attacker-planted-session-id"
    login_resp = client.post(
        "/login",
        json={"username": new_username, "password": "hunter22"},
        headers={"Cookie": f"session_id={pre_existing_session_id}"},
    )

    set_cookie_header = login_resp.headers.get("set-cookie", "")
    assert "session_id=" in set_cookie_header, "login must Set-Cookie a session id"
    issued_session_id = set_cookie_header.split("session_id=", 1)[1].split(";", 1)[0]
    assert issued_session_id != pre_existing_session_id


def test_expired_session_rejected(client, db_conn, new_username):
    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    client.post("/login", json={"username": new_username, "password": "hunter22"})

    session_id = client.cookies.get("session_id")
    db_conn.execute(
        "UPDATE sessions SET expires_at = ? WHERE id = ?", (time.time() - 1, session_id)
    )
    db_conn.commit()

    resp = client.get("/me")
    assert resp.status_code == 401


def test_login_produces_audit_event(client, new_username):
    from app.main import audit_log

    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    client.post("/login", json={"username": new_username, "password": "hunter22"})

    events = audit_log.recent(limit=20)
    login_events = [e for e in events if e.action == "login" and e.decision == "allow"]
    assert login_events, "expected an 'allow' audit event for the successful login"
    assert login_events[0].trace_id is not None
