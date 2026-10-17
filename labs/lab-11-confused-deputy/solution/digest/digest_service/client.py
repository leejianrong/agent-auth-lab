"""The nightly digest job: a service that acts as itself, with no human.

It trades its own credentials for an access token (OAuth 2.0 client
credentials), then calls the app's internal stats endpoint with that token.
The same trace id rides on both calls, so the audit trail can show them as
one story across the IdP and the app.
"""

import secrets

import httpx

DEFAULT_IDP_URL = "http://localhost:9000"
DEFAULT_API_URL = "http://localhost:8000"
CLIENT_ID = "digest-service"
# ADR-0008: the demo secret is fixed, checked in and localhost-only. A real
# job reads its secret from the environment or a secrets manager at start-up.
DEMO_SECRET = "digest-service-secret-do-not-reuse"


class DigestError(Exception):
    """The job could not complete; `step` says which hop refused it."""

    def __init__(self, step: str, detail: str):
        super().__init__(f"{step}: {detail}")
        self.step = step
        self.detail = detail


def fetch_token(
    http: httpx.Client, idp_url: str, client_id: str, secret: str, scope: str, trace_id: str,
) -> tuple[str, str]:
    """Returns `(access_token, granted_scope)`. The granted scope can be
    narrower than what we asked for, and we should report what we actually got."""
    res = http.post(
        f"{idp_url}/token",
        data={"grant_type": "client_credentials", "scope": scope},
        auth=(client_id, secret),
        headers={"X-Trace-Id": trace_id},
    )
    if res.status_code != 200:
        raise DigestError("token request", f"IdP answered {res.status_code} {res.json().get('error', '')}".strip())
    body = res.json()
    return body["access_token"], body.get("scope", "")


def fetch_stats(http: httpx.Client, api_url: str, token: str, trace_id: str) -> dict:
    res = http.get(
        f"{api_url}/internal/stats",
        headers={"Authorization": f"Bearer {token}", "X-Trace-Id": trace_id},
    )
    if res.status_code != 200:
        raise DigestError("stats request", f"app answered {res.status_code}: {res.json().get('detail', '')}")
    return res.json()


def run_digest(
    *,
    idp_http: httpx.Client,
    api_http: httpx.Client,
    idp_url: str = DEFAULT_IDP_URL,
    api_url: str = DEFAULT_API_URL,
    client_id: str = CLIENT_ID,
    secret: str = DEMO_SECRET,
    scope: str = "stats:read",
    trace_id: str | None = None,
) -> dict:
    trace_id = trace_id or secrets.token_hex(16)
    token, granted = fetch_token(idp_http, idp_url, client_id, secret, scope, trace_id)
    stats = fetch_stats(api_http, api_url, token, trace_id)
    return {"trace_id": trace_id, "scope": granted, "stats": stats}
