"""Run the agent on a schedule:

    python -m agent_runner --ticks 3 --interval 5
    python -m agent_runner --secret wrong-secret         # watch it get refused
    python -m agent_runner --probe                       # watch the policy refuse it
    python -m agent_runner --tasks                       # act for a person who asked (lab 09)
    python -m agent_runner --llm                         # optional: a real model picks the actions
"""

import argparse
import os
import sys

import httpx

from .agent import NotesSummaryAgent, ProbingAgent, ScriptedAgent
from .auth import TokenManager
from .runner import do_next_task, run_schedule

CLIENT_ID = "tidy-agent"
# ADR-0008: fixed, checked-in, localhost-only demo secret.
DEMO_SECRET = "tidy-agent-secret-do-not-reuse"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lab 09 tidy agent")
    ap.add_argument("--idp-url", default=os.environ.get("LAB_IDP_URL", "http://localhost:9000"))
    ap.add_argument("--api-url", default=os.environ.get("LAB_API_URL", "http://localhost:8000"))
    ap.add_argument("--secret", default=os.environ.get("AGENT_CLIENT_SECRET", DEMO_SECRET))
    ap.add_argument("--ticks", type=int, default=1)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument(
        "--probe", action="store_true",
        help="misbehave on purpose: ask for a too-long report and an ungranted tool, skipping the runner's own offer check",
    )
    ap.add_argument("--tasks", action="store_true", help="claim one pending task and act for the person who asked")
    ap.add_argument("--llm", action="store_true", help="optional stretch path: let a model choose the actions")
    args = ap.parse_args(argv)

    def show(n, history, offered):
        print(f"run {n}: offered tools: {', '.join(t.name for t in offered) or '(none)'}")
        for obs in history:
            print(f"  {obs.action.tool}: {'ok' if obs.ok else 'FAILED ' + str(obs.error)}")

    with httpx.Client(timeout=5.0) as http:
        tokens = TokenManager(http, args.idp_url, CLIENT_ID, args.secret, "stats:read reports:write")
        try:
            if args.tasks:
                task, history, offered = do_next_task(
                    NotesSummaryAgent(), tokens, http, args.idp_url, args.api_url, CLIENT_ID, args.secret,
                )
                if task is None:
                    print("no pending tasks")
                else:
                    print(f"task {task['id']} (trace {task['trace_id']}): acting for the person who asked")
                    show(1, history, offered)
                return 0
            if args.llm:
                from .llm_agent import LlmAgent
                from .tools import TOOLS, tools_for_scopes

                tokens.get("0" * 32)
                agent = LlmAgent(tools_for_scopes(TOOLS, tokens.granted_scope))
            else:
                agent = ProbingAgent() if args.probe else ScriptedAgent()
            run_schedule(
                agent, tokens, http, args.api_url, ticks=args.ticks, interval=args.interval, on_run=show,
                enforce_offer=not args.probe,
            )
        except PermissionError as e:
            print(f"agent could not start: {e}", file=sys.stderr)
            return 1
        except httpx.HTTPError as e:
            print(f"agent could not reach a service: {e}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
