"""Self-check suite for lab 01. Run this against your own implementation
with:

    pytest tests/test_self_check.py -v

Every test here is one line of the "you're done when" checklist in the
lab 01 handout, made executable. The session-cookie tests inherited from
lab 00 stay in this file unchanged — lab 01 doesn't touch that code path,
it adds a second, stateless one alongside it.
"""

import time

import jwt

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


# --- lab 01: JWT issuance and verification --------------------------------


def _make_token(claims: dict) -> str:
    """Sign an arbitrary claim set with the app's real secret — lets a test
    construct exactly the malformed-but-genuinely-signed token it needs
    (missing a claim, already expired) without going through /token."""
    return jwt.encode(claims, security.JWT_SECRET, algorithm=security.JWT_ALGORITHM)


def _login(client, new_username) -> None:
    client.post("/signup", json={"username": new_username, "password": "hunter22"})
    client.post("/login", json={"username": new_username, "password": "hunter22"})


def test_token_requires_login(client):
    resp = client.post("/token")
    assert resp.status_code == 401


def test_issued_token_carries_sub_and_exp(client, new_username):
    _login(client, new_username)
    resp = client.post("/token")
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    # Claims are readable without the secret — that's the whole teaching
    # point, and this is exactly what the decoder panel does client-side.
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == new_username
    assert "exp" in claims


def test_verify_accepts_a_freshly_issued_token(client, new_username):
    _login(client, new_username)
    token = client.post("/token").json()["access_token"]

    resp = client.post("/verify", json={"token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["signature_valid"] is True
    assert body["expired"] is False
    assert body["claims"]["sub"] == new_username


def test_verify_rejects_tampered_signature(client, new_username):
    _login(client, new_username)
    token = client.post("/token").json()["access_token"]

    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"

    resp = client.post("/verify", json={"token": tampered})
    body = resp.json()
    assert body["valid"] is False
    assert body["signature_valid"] is False
    assert body["reason"] == "invalid signature"


def test_verify_rejects_expired_token(client, new_username):
    now = int(time.time())
    expired_token = _make_token({"sub": new_username, "iat": now - 100, "exp": now - 1})

    resp = client.post("/verify", json={"token": expired_token})
    body = resp.json()
    assert body["valid"] is False
    assert body["signature_valid"] is True
    assert body["expired"] is True
    assert body["reason"] == "token expired"


def test_verify_rejects_missing_required_claim(client, new_username):
    now = int(time.time())
    token_without_sub = _make_token({"iat": now, "exp": now + 900})

    resp = client.post("/verify", json={"token": token_without_sub})
    body = resp.json()
    assert body["valid"] is False
    assert body["signature_valid"] is True
    assert body["expired"] is False
    assert body["reason"] == "missing required claim: sub"


def test_verify_denials_produce_distinct_audit_reasons(client, new_username):
    from app.main import audit_log

    _login(client, new_username)
    token = client.post("/token").json()["access_token"]
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"

    now = int(time.time())
    expired_token = _make_token({"sub": new_username, "exp": now - 1})
    token_without_sub = _make_token({"exp": now + 900})

    client.post("/verify", json={"token": tampered})
    client.post("/verify", json={"token": expired_token})
    client.post("/verify", json={"token": token_without_sub})

    events = audit_log.recent(limit=20)
    verify_denials = [e for e in events if e.action == "verify_token" and e.decision == "deny"]
    reasons = {e.reason for e in verify_denials}
    assert "invalid signature" in reasons
    assert "token expired" in reasons
    assert "missing required claim: sub" in reasons
    assert len(reasons) == 3, "each failure mode must log its own distinct reason"


def test_verify_unit_level_distinct_errors():
    """Same three cases as above, called directly against verify_token() —
    the exact unit test SLICES.md's test plan asks for."""
    now = time.time()
    valid_token = jwt.encode(
        {"sub": "alice", "exp": now + 900}, security.JWT_SECRET, algorithm=security.JWT_ALGORITHM
    )
    header, payload, signature = valid_token.split(".")
    tampered = f"{header}.{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    expired = jwt.encode(
        {"sub": "alice", "exp": now - 1}, security.JWT_SECRET, algorithm=security.JWT_ALGORITHM
    )
    missing_claim = jwt.encode(
        {"exp": now + 900}, security.JWT_SECRET, algorithm=security.JWT_ALGORITHM
    )

    bad_sig = security.verify_token(tampered)
    expired_result = security.verify_token(expired)
    missing_result = security.verify_token(missing_claim)

    assert bad_sig.valid is False and bad_sig.reason == "invalid signature"
    assert expired_result.valid is False and expired_result.reason == "token expired"
    assert missing_result.valid is False and missing_result.reason == "missing required claim: sub"
    assert len({bad_sig.reason, expired_result.reason, missing_result.reason}) == 3
