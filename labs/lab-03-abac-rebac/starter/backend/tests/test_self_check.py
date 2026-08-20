"""Self-check suite for lab 03. Run this against your own implementation
with:

    pytest tests/test_self_check.py -v

Every test here is one line of the "you're done when" checklist in the
lab 03 handout, made executable. The session-cookie, JWT, and RBAC tests
inherited from labs 00-02 stay in this file unchanged — lab 03 doesn't
touch any of that, it adds a new, finer-grained policy evaluator alongside
it.
"""

import time

import jwt

from app import policy, security


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


def test_verify_reports_malformed_exp_as_its_own_reason_not_bad_signature():
    """Regression test carried in from a lab 01 fix: a token can be
    genuinely signed with the real secret and still carry a malformed
    (non-numeric) `exp` claim. That must be reported as its own distinct
    reason, not misattributed to the signature.

    Calls `verify_token()` directly (not through `/verify`) so it doesn't
    add an extra audit event that the RBAC audit-reason tests below, or
    lab 01's own audit-reason test above, would otherwise pick up via
    `audit_log.recent()`.
    """
    token_with_bad_exp = jwt.encode(
        {"sub": "alice", "exp": "soon"}, security.JWT_SECRET, algorithm=security.JWT_ALGORITHM
    )

    result = security.verify_token(token_with_bad_exp)
    assert result.valid is False
    assert result.signature_valid is True, "the signature itself was genuine"
    assert result.reason == "malformed exp claim"


# --- lab 02: roles and RBAC ------------------------------------------------


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "lab02-admin-do-not-reuse"


def _login_as_seeded_admin(client) -> None:
    resp = client.post("/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert resp.status_code == 200, "the seeded admin account must be able to log in"


def test_signup_defaults_to_user_role(client, new_username):
    resp = client.post("/signup", json={"username": new_username, "password": "hunter22"})
    assert resp.status_code == 201
    assert resp.json()["role"] == "user"


def test_me_reports_caller_role(client, new_username):
    _login(client, new_username)
    resp = client.get("/me")
    assert resp.status_code == 200
    assert resp.json()["role"] == "user"


def test_admin_can_list_users(client):
    _login_as_seeded_admin(client)
    resp = client.get("/admin/users")
    assert resp.status_code == 200
    usernames = {row["username"] for row in resp.json()}
    assert ADMIN_USERNAME in usernames


def test_plain_user_denied_admin_panel(client, new_username):
    """The exact integration case SLICES.md's test plan names: a user
    without the admin role is denied the admin panel, and that denial is
    visible in the audit log."""
    from app.main import audit_log

    _login(client, new_username)
    resp = client.get("/admin/users")
    assert resp.status_code == 403

    events = audit_log.recent(limit=20)
    denials = [e for e in events if e.action == "list_users" and e.decision == "deny"]
    assert denials, "expected a deny audit event for the rejected admin-panel request"
    assert "admin" in denials[0].reason
    assert "user" in denials[0].reason


def test_admin_panel_denial_reason_names_both_roles(client, new_username):
    from app.main import audit_log

    _login(client, new_username)
    client.get("/admin/users")

    events = audit_log.recent(limit=20)
    denial = next(e for e in events if e.action == "list_users" and e.decision == "deny")
    assert denial.reason == "requires role in ['admin'], caller has role 'user'"
    assert denial.resource == "admin_panel"


def test_admin_panel_requires_login_before_role_check(client):
    """No session at all must fail with 401 (authenticate first), not 403
    (authorize) — the RBAC dependency chains off `get_current_session` and
    never runs the role check for an unauthenticated caller."""
    resp = client.get("/admin/users")
    assert resp.status_code == 401


def test_role_is_authorized_exact_match():
    """Unit test SLICES.md's test plan names directly: RBAC denies
    correctly for a role not in the allow-list — and only allows a role
    that's actually in it, not merely non-empty."""
    assert security.role_is_authorized("admin", ("admin",)) is True
    assert security.role_is_authorized("user", ("admin",)) is False
    assert security.role_is_authorized("user", ("admin", "user")) is True
    assert security.role_is_authorized("", ("admin",)) is False


# --- lab 03: ABAC/ReBAC policy evaluator -----------------------------------


def _create_note(client, title="my note", body="hello") -> int:
    resp = client.post("/notes", json={"title": title, "body": body})
    assert resp.status_code == 201
    return resp.json()["id"]


def test_policy_evaluator_admin_rule_matches_regardless_of_ownership():
    """Unit test, SLICES.md's exact wording: the evaluator returns the
    correct allow/deny plus matched-rule ID for a representative set of
    ABAC inputs — starting with the admin case."""
    subject = policy.Subject(id=99, role="admin")
    resource = policy.ResourceAttrs(owner_id=1)  # someone else's resource
    decision = policy.evaluate(subject, resource, "read")
    assert decision.allow is True
    assert decision.rule_id == "admin-full-access"


def test_policy_evaluator_owner_rule_matches_for_the_actual_owner():
    subject = policy.Subject(id=1, role="user")
    resource = policy.ResourceAttrs(owner_id=1)
    decision = policy.evaluate(subject, resource, "write")
    assert decision.allow is True
    assert decision.rule_id == "owner-full-access"


def test_policy_evaluator_default_deny_for_a_non_owner_non_admin():
    subject = policy.Subject(id=2, role="user")
    resource = policy.ResourceAttrs(owner_id=1)  # not subject's resource
    decision = policy.evaluate(subject, resource, "read")
    assert decision.allow is False
    assert decision.rule_id == "default-deny"


def test_owner_can_read_and_update_own_note(client, new_username):
    _login(client, new_username)
    note_id = _create_note(client)

    read_resp = client.get(f"/notes/{note_id}")
    assert read_resp.status_code == 200
    read_body = read_resp.json()
    assert read_body["allowed"] is True
    assert read_body["rule_id"] == "owner-full-access"
    assert read_body["note"]["title"] == "my note"

    update_resp = client.put(f"/notes/{note_id}", json={"title": "renamed", "body": "changed"})
    assert update_resp.status_code == 200
    update_body = update_resp.json()
    assert update_body["allowed"] is True
    assert update_body["rule_id"] == "owner-full-access"
    assert update_body["note"]["title"] == "renamed"


def test_admin_can_read_and_update_someone_elses_note(client, new_username):
    _login(client, new_username)
    note_id = _create_note(client, title="owned by a regular user")

    _login_as_seeded_admin(client)
    read_resp = client.get(f"/notes/{note_id}")
    assert read_resp.status_code == 200
    assert read_resp.json()["rule_id"] == "admin-full-access"

    update_resp = client.put(f"/notes/{note_id}", json={"title": "admin edited this", "body": "x"})
    assert update_resp.status_code == 200
    assert update_resp.json()["rule_id"] == "admin-full-access"


def test_non_owner_denied_reading_someone_elses_note(client, new_username):
    """The exact integration case SLICES.md's test plan names: a non-owner
    request for another user's resource is denied by the policy evaluator,
    and the response names the specific rule that fired."""
    owner_username = new_username
    _login(client, owner_username)
    note_id = _create_note(client, title="private note")
    client.post("/logout")

    other_username = f"{new_username}-other"
    client.post("/signup", json={"username": other_username, "password": "hunter22"})
    client.post("/login", json={"username": other_username, "password": "hunter22"})

    resp = client.get(f"/notes/{note_id}")
    assert resp.status_code == 403
    body = resp.json()["detail"]
    assert body["allowed"] is False
    assert body["rule_id"] == "default-deny"


def test_non_owner_denied_updating_someone_elses_note(client, new_username):
    owner_username = new_username
    _login(client, owner_username)
    note_id = _create_note(client, title="private note")
    client.post("/logout")

    other_username = f"{new_username}-other"
    client.post("/signup", json={"username": other_username, "password": "hunter22"})
    client.post("/login", json={"username": other_username, "password": "hunter22"})

    resp = client.put(f"/notes/{note_id}", json={"title": "hijacked", "body": "hijacked"})
    assert resp.status_code == 403
    body = resp.json()["detail"]
    assert body["allowed"] is False
    assert body["rule_id"] == "default-deny"


def test_denied_note_access_produces_an_audit_event_naming_the_matched_rule(client, new_username):
    """The self-check assertion SLICES.md's test plan names directly: the
    audit log records the matched-rule ID for a denial, not just "deny"."""
    from app.main import audit_log

    owner_username = new_username
    _login(client, owner_username)
    note_id = _create_note(client, title="private note")
    client.post("/logout")

    other_username = f"{new_username}-other"
    client.post("/signup", json={"username": other_username, "password": "hunter22"})
    client.post("/login", json={"username": other_username, "password": "hunter22"})
    client.get(f"/notes/{note_id}")

    events = audit_log.recent(limit=20)
    denial = next(e for e in events if e.action == "read_note" and e.decision == "deny")
    assert denial.metadata["rule_id"] == "default-deny"
    assert denial.metadata["rule_description"]
    assert denial.resource == f"note:{note_id}"


def test_allowed_note_access_produces_an_audit_event_naming_the_matched_rule(client, new_username):
    from app.main import audit_log

    _login(client, new_username)
    note_id = _create_note(client)
    client.get(f"/notes/{note_id}")

    events = audit_log.recent(limit=20)
    allow_event = next(e for e in events if e.action == "read_note" and e.decision == "allow")
    assert allow_event.metadata["rule_id"] == "owner-full-access"


def test_reading_a_nonexistent_note_is_404_not_a_policy_decision(client, new_username):
    _login(client, new_username)
    resp = client.get("/notes/999999")
    assert resp.status_code == 404


def test_note_endpoints_require_login(client):
    assert client.get("/notes/1").status_code == 401
    assert client.put("/notes/1", json={"title": "x", "body": "y"}).status_code == 401
    assert client.post("/notes", json={"title": "x", "body": "y"}).status_code == 401
    assert client.get("/notes/mine").status_code == 401
