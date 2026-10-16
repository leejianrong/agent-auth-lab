"""Getting and keeping an access token for an agent that runs unattended.

Nobody is around to log in again when a token runs out, so the agent has to
notice for itself, and it has to notice *before* the token dies, not after a
request has already failed.
"""

import time
from collections.abc import Callable

import httpx

TOKEN_REFRESH_SKEW_SECONDS = 30


def needs_new_token(expires_at: float | None, now: float) -> bool:
    """Should the agent fetch a fresh token before its next call?"""
    # LAB:SOLUTION >>>
    return expires_at is None or now >= expires_at - TOKEN_REFRESH_SKEW_SECONDS
    # LAB:SOLUTION <<<
    # LAB:STARTER >>>
    # TODO(lab-07): this only refreshes once the token has already expired.
    # A token that is valid now can be dead by the time a request reaches the
    # server (clocks differ, calls take time), and an unattended agent then
    # fails with a 401 and no one to retry it. Refresh when the token is
    # within TOKEN_REFRESH_SKEW_SECONDS of expiring, and when there is no
    # token at all (`expires_at` is None).
    return expires_at is None or now >= expires_at
    # LAB:STARTER <<<


class TokenManager:
    """Holds the agent's current token and replaces it when needed. The clock
    is injectable so the refresh behaviour can be tested without waiting."""

    def __init__(
        self, http: httpx.Client, idp_url: str, client_id: str, secret: str, scope: str,
        *, clock: Callable[[], float] = time.time,
    ):
        self._http, self._idp_url = http, idp_url
        self._client_id, self._secret, self._scope = client_id, secret, scope
        self._clock = clock
        self.token: str | None = None
        self.granted_scope: str = ""
        self.expires_at: float | None = None
        self.fetches = 0

    def get(self, trace_id: str) -> str:
        if self.token is None or needs_new_token(self.expires_at, self._clock()):
            self._fetch(trace_id)
        assert self.token is not None
        return self.token

    def _fetch(self, trace_id: str) -> None:
        res = self._http.post(
            f"{self._idp_url}/token",
            data={"grant_type": "client_credentials", "scope": self._scope},
            auth=(self._client_id, self._secret),
            headers={"X-Trace-Id": trace_id},
        )
        if res.status_code != 200:
            raise PermissionError(f"IdP refused the agent's credentials ({res.status_code})")
        body = res.json()
        self.token = body["access_token"]
        self.granted_scope = body.get("scope", "")
        self.expires_at = self._clock() + int(body["expires_in"])
        self.fetches += 1
