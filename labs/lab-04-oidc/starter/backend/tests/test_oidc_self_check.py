"""Self-check suite for lab 04: Sign in with the Lab IdP.

    pytest tests/test_oidc_self_check.py -v

Every test is one line of the "you're done when" checklist in the lab 04
handout, made executable. The three groups map to the three tasks:

  1. PKCE verification at the IdP        (idp/lab_idp/oauth.py)
  2. The client's PKCE challenge          (app/oidc_client.py: make_pkce_pair)
  3. ID token validation at the client    (app/oidc_client.py: validate_id_token)
"""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import oidc_client

REDIRECT = "http://localhost:8000/auth/oidc/callback"


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def start_login(client):
    """Browser step 1: hit the app's login endpoint, get bounced to the IdP."""
    res = client.get("/auth/oidc/login")
    assert res.status_code == 302
    return res.headers["location"]


def idp_sign_in(idp, authorize_url, username="alice", password="alice-lab-pass"):
    """Browser steps 2-3: open the IdP page, submit the login form. Returns the
    IdP's response (a redirect to the app's callback when it worked)."""
    params = query(authorize_url)
    page = idp.get(authorize_url)
    assert page.status_code == 200
    return idp.post(
        f"/authorize/login?trace_id={params.get('trace_id', '')}",
        data={**params, "username": username, "password": password},
    )


def callback(client, redirect_location):
    """Browser step 4: follow the IdP's redirect back to the app."""
    parsed = urlparse(redirect_location)
    return client.get(f"{parsed.path}?{parsed.query}")


def full_login(client, idp, **kwargs):
    authorize_url = start_login(client)
    signed_in = idp_sign_in(idp, authorize_url, **kwargs)
    assert signed_in.status_code == 302, signed_in.text
    return authorize_url, signed_in.headers["location"], callback(client, signed_in.headers["location"])


# --- task 1: PKCE verification at the IdP -------------------------------------

def test_verify_pkce_accepts_the_matching_verifier(idp_module):
    verifier = "a" * 64
    assert idp_module.oauth.verify_pkce(verifier, s256(verifier)) is True


def test_verify_pkce_rejects_a_different_verifier(idp_module):
    assert idp_module.oauth.verify_pkce("b" * 64, s256("a" * 64)) is False


def test_token_endpoint_rejects_a_stolen_code_without_the_verifier(client, idp):
    """The whole point of PKCE: someone who intercepts the code but never
    saw the verifier can't redeem it."""
    authorize_url = start_login(client)
    code = parse_qs(urlparse(idp_sign_in(idp, authorize_url).headers["location"]).query)["code"][0]
    res = idp.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": "lab-client", "code_verifier": "attacker-guess-" + "x" * 40,
    })
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_grant"}


def test_pkce_mismatch_is_audited_with_a_specific_reason(client, idp):
    authorize_url = start_login(client)
    trace_id = query(authorize_url)["trace_id"]
    code = parse_qs(urlparse(idp_sign_in(idp, authorize_url).headers["location"]).query)["code"][0]
    idp.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": "lab-client", "code_verifier": "wrong-" + "y" * 50,
    }, headers={"X-Trace-Id": trace_id})
    events = idp.get(f"/observability/traces/{trace_id}").json()
    denied = [e for e in events if e["action"] == "oidc_token_exchange" and e["decision"] == "deny"]
    assert denied and "PKCE mismatch" in denied[0]["reason"]


def test_an_authorization_code_can_only_be_redeemed_once(client, idp):
    authorize_url = start_login(client)
    params = query(authorize_url)
    code = parse_qs(urlparse(idp_sign_in(idp, authorize_url).headers["location"]).query)["code"][0]
    # We don't know the real verifier from here, so the first attempt fails PKCE.
    # What matters is that a failed attempt burns the code: a thief gets one guess.
    body = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": "lab-client", "code_verifier": "z" * 50}
    trace = {"X-Trace-Id": params["trace_id"]}
    assert idp.post("/token", data=body, headers=trace).status_code == 400
    assert idp.post("/token", data=body, headers=trace).status_code == 400
    trace_events = idp.get(f"/observability/traces/{params['trace_id']}").json()
    reasons = [e["reason"] for e in trace_events if e["decision"] == "deny"]
    assert any("already used" in (r or "") for r in reasons)


# --- task 2: the client's PKCE challenge --------------------------------------

def test_make_pkce_pair_challenge_is_the_s256_hash_of_the_verifier():
    verifier, challenge = oidc_client.make_pkce_pair()
    assert challenge == s256(verifier)
    assert challenge != verifier


def test_make_pkce_pair_verifier_is_long_and_never_repeats():
    a, _ = oidc_client.make_pkce_pair()
    b, _ = oidc_client.make_pkce_pair()
    assert a != b
    assert 43 <= len(a) <= 128  # RFC 7636 section 4.1


def test_the_authorize_redirect_carries_the_challenge_never_the_verifier(client, db_conn):
    authorize_url = start_login(client)
    params = query(authorize_url)
    flow = db_conn.execute("SELECT * FROM oidc_flows WHERE state = ?", (params["state"],)).fetchone()
    assert params["code_challenge_method"] == "S256"
    assert params["code_challenge"] == s256(flow["code_verifier"])
    assert flow["code_verifier"] not in authorize_url


def test_login_works_end_to_end_with_a_real_s256_challenge(client, idp):
    _, _, result = full_login(client, idp)
    assert "oidc_error" not in result.headers["location"], result.headers["location"]


# --- task 3: ID token validation at the client --------------------------------

def _forge(claims_override=None, *, key=None, kid=None, alg="RS256", drop=()):
    """Mint an ID token the way a careful attacker would: valid shape, one
    thing wrong. `key=None` signs with the IdP's real key so only the claim
    check can catch it."""
    from lab_idp import main as idp_main
    now = int(time.time())
    claims = {
        "iss": oidc_client.ISSUER, "sub": "idp-alice", "aud": oidc_client.CLIENT_ID,
        "iat": now, "exp": now + 300, "nonce": "expected-nonce", "preferred_username": "alice",
    }
    claims.update(claims_override or {})
    for k in drop:
        claims.pop(k, None)
    signing = key if key is not None else idp_main.signing_key.private_pem
    return jwt.encode(claims, signing, algorithm=alg, headers={"kid": kid or idp_main.signing_key.kid})


def test_a_correctly_signed_token_with_the_right_claims_is_accepted():
    claims = oidc_client.validate_id_token(_forge(), expected_nonce="expected-nonce")
    assert claims["sub"] == "idp-alice"


def test_a_token_signed_by_someone_else_is_rejected():
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = attacker.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(oidc_client.OidcError, match="signature"):
        oidc_client.validate_id_token(_forge(key=pem), expected_nonce="expected-nonce")


def test_a_token_for_a_different_audience_is_rejected():
    with pytest.raises(oidc_client.OidcError, match="audience"):
        oidc_client.validate_id_token(_forge({"aud": "some-other-app"}), expected_nonce="expected-nonce")


def test_a_token_from_a_different_issuer_is_rejected():
    with pytest.raises(oidc_client.OidcError, match="issuer"):
        oidc_client.validate_id_token(_forge({"iss": "http://evil.example"}), expected_nonce="expected-nonce")


def test_an_expired_token_is_rejected():
    past = int(time.time()) - 3600
    with pytest.raises(oidc_client.OidcError, match="expired"):
        oidc_client.validate_id_token(_forge({"iat": past - 300, "exp": past}), expected_nonce="expected-nonce")


def test_a_token_for_a_different_login_attempt_is_rejected():
    with pytest.raises(oidc_client.OidcError, match="nonce"):
        oidc_client.validate_id_token(_forge({"nonce": "someone-elses"}), expected_nonce="expected-nonce")


def test_a_token_with_no_nonce_is_rejected():
    with pytest.raises(oidc_client.OidcError, match="nonce"):
        oidc_client.validate_id_token(_forge(drop=("nonce",)), expected_nonce="expected-nonce")


def test_a_token_using_the_alg_none_trick_is_rejected():
    now = int(time.time())
    claims = {"iss": oidc_client.ISSUER, "sub": "idp-alice", "aud": oidc_client.CLIENT_ID,
              "iat": now, "exp": now + 300, "nonce": "expected-nonce"}
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"kid": "whatever"})
    with pytest.raises(oidc_client.OidcError):
        oidc_client.validate_id_token(unsigned, expected_nonce="expected-nonce")


def test_a_token_signed_with_a_symmetric_algorithm_is_rejected():
    """Algorithm confusion: HS256 where the "secret" is the IdP's public key.
    PyJWT refuses to build this token for us, so assemble it by hand."""
    import hmac
    from lab_idp import main as idp_main

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    public_pem = idp_main.signing_key.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": idp_main.signing_key.kid}).encode())
    payload = b64(json.dumps({
        "iss": oidc_client.ISSUER, "sub": "idp-alice", "aud": oidc_client.CLIENT_ID,
        "iat": now, "exp": now + 300, "nonce": "expected-nonce",
    }).encode())
    signature = b64(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    with pytest.raises(oidc_client.OidcError, match="algorithm"):
        oidc_client.validate_id_token(f"{header}.{payload}.{signature}", expected_nonce="expected-nonce")


def test_a_token_signed_with_an_unpublished_key_id_is_rejected():
    with pytest.raises(oidc_client.OidcError, match="key"):
        oidc_client.validate_id_token(_forge(kid="not-a-real-kid"), expected_nonce="expected-nonce")


# --- the whole flow: what the learner sees in the browser ----------------------

def test_login_through_the_idp_creates_a_session_for_a_federated_user(client, idp):
    _, _, result = full_login(client, idp)
    assert result.status_code == 302
    location = result.headers["location"]
    assert location.startswith("http://localhost:5173/")
    assert "oidc_trace" in location and "oidc_error" not in location
    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice@lab-idp"
    assert me.json()["role"] == "user"


def test_the_same_idp_user_maps_to_the_same_local_user_each_time(client, idp, db_conn):
    full_login(client, idp)
    full_login(client, idp)
    rows = db_conn.execute("SELECT id FROM users WHERE idp_sub = 'idp-alice'").fetchall()
    assert len(rows) == 1


def test_a_federated_user_cannot_log_in_with_a_password(client, idp):
    full_login(client, idp)
    res = client.post("/login", json={"username": "alice@lab-idp", "password": "alice-lab-pass"})
    assert res.status_code == 401


def test_the_trace_shows_both_services_in_order(client, idp):
    authorize_url, _, result = full_login(client, idp)
    trace_id = query(result.headers["location"])["oidc_trace"]
    assert trace_id == query(authorize_url)["trace_id"]
    trace = client.get(f"/oidc/trace/{trace_id}").json()
    assert trace["outcome"] == "success"
    assert trace["idp_reachable"] is True
    actions = [(e["source"], e["action"]) for e in trace["events"]]
    for expected in [
        ("client", "oidc_start"), ("idp", "oidc_authorize"), ("idp", "oidc_login"),
        ("idp", "oidc_token_exchange"), ("client", "oidc_token_request"), ("client", "id_token_validate"),
    ]:
        assert expected in actions, f"{expected} missing from {actions}"
    assert actions.index(("client", "oidc_start")) < actions.index(("idp", "oidc_login")) < actions.index(("idp", "oidc_token_exchange"))
    assert trace["id_token_claims"]["sub"] == "idp-alice"


def test_the_trace_never_contains_the_code_the_verifier_or_a_token(client, idp, db_conn):
    authorize_url, redirect, result = full_login(client, idp)
    trace_id = query(result.headers["location"])["oidc_trace"]
    flow = db_conn.execute("SELECT code_verifier FROM oidc_flows WHERE trace_id = ?", (trace_id,)).fetchone()
    blob = json.dumps(client.get(f"/oidc/trace/{trace_id}").json())
    assert flow["code_verifier"] not in blob
    assert query(redirect)["code"] not in blob
    assert "eyJ" not in blob  # no JWT anywhere in the response


def test_a_callback_with_an_unknown_state_is_rejected(client):
    res = client.get("/auth/oidc/callback?code=whatever&state=not-a-real-state")
    assert res.status_code == 302
    assert "oidc_error=login_failed" in res.headers["location"]
    assert client.get("/me").status_code == 401


def test_a_callback_cannot_be_replayed(client, idp):
    _, redirect, first = full_login(client, idp)
    assert "oidc_error" not in first.headers["location"]
    replay = callback(client, redirect)
    assert "oidc_error=login_failed" in replay.headers["location"]
    trace_id = query(replay.headers["location"])["oidc_trace"]
    trace = client.get(f"/oidc/trace/{trace_id}").json()
    assert any("already used" in (e["reason"] or "") for e in trace["events"] if e["decision"] == "deny")


def test_a_wrong_idp_password_issues_no_code(client, idp):
    authorize_url = start_login(client)
    res = idp_sign_in(idp, authorize_url, password="not-the-password")
    assert res.status_code == 401
    assert "code=" not in res.headers.get("location", "")


# --- the IdP's own guard rails -------------------------------------------------

def test_the_idp_never_redirects_to_an_unregistered_redirect_uri(idp):
    res = idp.get("/authorize", params={
        "client_id": "lab-client", "redirect_uri": "http://evil.example/steal", "response_type": "code",
        "code_challenge": "x" * 43, "code_challenge_method": "S256", "state": "s",
    })
    assert res.status_code == 400
    assert "location" not in res.headers


def test_the_idp_requires_a_pkce_challenge(idp):
    res = idp.get("/authorize", params={
        "client_id": "lab-client", "redirect_uri": REDIRECT, "response_type": "code", "state": "s",
    })
    assert res.status_code == 302
    assert "error=invalid_request" in res.headers["location"]


def test_the_idp_refuses_the_plain_challenge_method(idp):
    res = idp.get("/authorize", params={
        "client_id": "lab-client", "redirect_uri": REDIRECT, "response_type": "code",
        "code_challenge": "x" * 43, "code_challenge_method": "plain", "state": "s",
    })
    assert res.status_code == 302
    assert "error=invalid_request" in res.headers["location"]


def test_the_idp_publishes_discovery_and_signing_keys(idp):
    config = idp.get("/.well-known/openid-configuration").json()
    assert config["code_challenge_methods_supported"] == ["S256"]
    keys = idp.get("/jwks.json").json()["keys"]
    assert keys and keys[0]["alg"] == "RS256" and "d" not in keys[0]  # never the private part
