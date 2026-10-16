"""Browser-side helpers shared by the OIDC self-check files: they play the
part of the browser, walking a login through the app and the IdP."""

import base64
import hashlib
import html
import re
from urllib.parse import parse_qs, urlparse

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


def hidden_fields(page_html: str) -> dict:
    return {m.group(1): html.unescape(m.group(2)) for m in re.finditer(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', page_html)}


def idp_sign_in(idp, authorize_url, username="alice", password="alice-lab-pass", approve=None, decision="allow"):
    """Browser steps 2-4: open the IdP page, submit the login form, and, if
    the IdP asks, answer the consent screen. `approve=None` ticks every box
    that can be ticked. Returns the IdP's final response (a redirect to the
    app's callback when it worked)."""
    params = query(authorize_url)
    page = idp.get(authorize_url)
    assert page.status_code == 200
    res = idp.post(
        f"/authorize/login?trace_id={params.get('trace_id', '')}",
        data={**params, "username": username, "password": password},
    )
    if res.status_code == 200 and "Allow access?" in res.text:
        boxes = re.findall(r'name="approve" value="([^"]+)" checked(?! disabled)', res.text)
        res = idp.post(
            f"/authorize/consent?trace_id={params.get('trace_id', '')}",
            data={**hidden_fields(res.text), "approve": boxes if approve is None else approve, "decision": decision},
        )
    return res


def callback(client, redirect_location):
    """Browser step 4: follow the IdP's redirect back to the app."""
    parsed = urlparse(redirect_location)
    return client.get(f"{parsed.path}?{parsed.query}")


def full_login(client, idp, **kwargs):
    authorize_url = start_login(client)
    signed_in = idp_sign_in(idp, authorize_url, **kwargs)
    assert signed_in.status_code == 302, signed_in.text
    return authorize_url, signed_in.headers["location"], callback(client, signed_in.headers["location"])
