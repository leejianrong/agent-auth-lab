"""Run the digest job once:

    python -m digest_service
    python -m digest_service --secret wrong-secret      # watch it get refused
    python -m digest_service --scope "stats:read notes:write"   # watch the extra scope get dropped
"""

import argparse
import os
import sys

import httpx

from .client import CLIENT_ID, DEFAULT_API_URL, DEFAULT_IDP_URL, DEMO_SECRET, DigestError, run_digest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lab 06 nightly digest job (a service client)")
    ap.add_argument("--idp-url", default=os.environ.get("LAB_IDP_URL", DEFAULT_IDP_URL))
    ap.add_argument("--api-url", default=os.environ.get("LAB_API_URL", DEFAULT_API_URL))
    ap.add_argument("--client-id", default=CLIENT_ID)
    ap.add_argument("--secret", default=os.environ.get("DIGEST_CLIENT_SECRET", DEMO_SECRET))
    ap.add_argument("--scope", default="stats:read")
    args = ap.parse_args(argv)

    with httpx.Client(timeout=5.0) as http:
        try:
            out = run_digest(
                idp_http=http, api_http=http, idp_url=args.idp_url, api_url=args.api_url,
                client_id=args.client_id, secret=args.secret, scope=args.scope,
            )
        except DigestError as e:
            print(f"digest failed at the {e.step}: {e.detail}", file=sys.stderr)
            return 1
        except httpx.HTTPError as e:
            print(f"digest could not reach a service: {e}", file=sys.stderr)
            return 2
    print(f"trace {out['trace_id']}")
    print(f"scope granted: {out['scope']}")
    print(f"users: {out['stats']['users']}, notes: {out['stats']['notes']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
