"""Run the agent on a schedule:

    python -m agent_runner --ticks 3 --interval 5
    python -m agent_runner --secret wrong-secret         # watch it get refused
    python -m agent_runner --probe                       # watch the policy refuse it
    python -m agent_runner --tasks                       # act for a person who asked (lab 09)
    python -m agent_runner --elevated                    # delete old reports: waits for a person (lab 10)
    python -m agent_runner --hand-off                    # act for a person, then pass the filing to the archive agent (lab 11)
    python -m agent_runner --archive                     # run as the archive agent: collect handed-over work (lab 11)
    python -m agent_runner --archive --unguarded         # ...and skip its own tool check, so the API has to refuse
    python -m agent_runner --llm                         # optional: a real model picks the actions
"""

import argparse
import os
import sys

import httpx

from .agent import ArchiveAgent, NotesSummaryAgent, ProbingAgent, ScriptedAgent, TidyUpAgent
from .approval import ApprovalWait
from .auth import TokenManager
from .runner import do_next_handoff, do_next_task, do_next_task_and_hand_off, run_once, run_schedule

CLIENT_ID = "tidy-agent"
# ADR-0008: fixed, checked-in, localhost-only demo secrets.
DEMO_SECRET = "tidy-agent-secret-do-not-reuse"
ARCHIVE_CLIENT_ID = "archive-agent"
ARCHIVE_SECRET = "archive-agent-secret-do-not-reuse"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lab 11 tidy agent")
    ap.add_argument("--idp-url", default=os.environ.get("LAB_IDP_URL", "http://localhost:9000"))
    ap.add_argument("--api-url", default=os.environ.get("LAB_API_URL", "http://localhost:8000"))
    ap.add_argument("--secret", default=os.environ.get("AGENT_CLIENT_SECRET"))
    ap.add_argument("--ticks", type=int, default=1)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument(
        "--probe", action="store_true",
        help="misbehave on purpose: ask for a too-long report and an ungranted tool, skipping the runner's own offer check",
    )
    ap.add_argument("--tasks", action="store_true", help="claim one pending task and act for the person who asked")
    ap.add_argument(
        "--elevated", action="store_true",
        help="delete old reports, an elevated action: the run waits until a person approves or denies it",
    )
    ap.add_argument("--wait", type=float, default=120.0, help="seconds to wait for a person's decision (with --elevated)")
    ap.add_argument("--hand-off", action="store_true", help="act for a person on an archive job, then hand the filing to the archive agent")
    ap.add_argument("--archive", action="store_true", help="run as the archive agent and do the work another agent handed over")
    ap.add_argument(
        "--unguarded", action="store_true",
        help="with --archive: skip the runner's own tool check, as a hijacked client would, so only the API can say no",
    )
    ap.add_argument("--llm", action="store_true", help="optional stretch path: let a model choose the actions")
    args = ap.parse_args(argv)

    def show(n, history, offered):
        print(f"run {n}: offered tools: {', '.join(t.name for t in offered) or '(none)'}")
        for obs in history:
            print(f"  {obs.action.tool}: {'ok' if obs.ok else 'FAILED ' + str(obs.error)}")

    with httpx.Client(timeout=5.0) as http:
        scope = "stats:read reports:write" + (" reports:purge" if args.elevated else "")
        client_id, secret = (ARCHIVE_CLIENT_ID, args.secret or ARCHIVE_SECRET) if args.archive else (CLIENT_ID, args.secret or DEMO_SECRET)
        if args.archive:
            scope = "reports:write"
        tokens = TokenManager(http, args.idp_url, client_id, secret, scope)
        try:
            if args.tasks:
                task, history, offered = do_next_task(
                    NotesSummaryAgent(), tokens, http, args.idp_url, args.api_url, client_id, secret,
                )
                if task is None:
                    print("no pending tasks")
                else:
                    print(f"task {task['id']} (trace {task['trace_id']}): acting for the person who asked")
                    show(1, history, offered)
                return 0
            if args.archive:
                work, history, offered = do_next_handoff(ArchiveAgent(), tokens, http, args.api_url, enforce_offer=not args.unguarded)
                if work is None:
                    print("nothing has been handed to the archive agent")
                else:
                    print(f"hand-off {work['id']} from {work['from_agent']} (trace {work['trace_id']}), scope: {work['scope']}")
                    show(1, history, offered)
                return 0
            if args.hand_off:
                task, history, offered = do_next_task_and_hand_off(
                    NotesSummaryAgent(), tokens, http, args.idp_url, args.api_url, client_id, secret,
                )
                if task is None:
                    print("no pending archive tasks")
                else:
                    print(f"task {task['id']} (trace {task['trace_id']}): acting for the person who asked")
                    show(1, history, offered)
                    print(f"  hand-off to the archive agent: " + (f"#{task['handoff_id']}" if "handoff_id" in task else f"REFUSED ({task['handoff_error']})"))
                return 0
            if args.elevated:
                def waiting(approval_id, tool):
                    print(f"  {tool} needs approval: request {approval_id} is in the queue, waiting for a person...", flush=True)

                history, offered = run_once(
                    TidyUpAgent(), tokens, http, args.api_url,
                    approval_wait=ApprovalWait(timeout=args.wait, on_pending=waiting),
                )
                show(1, history, offered)
                return 0 if all(o.ok for o in history) else 3
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
