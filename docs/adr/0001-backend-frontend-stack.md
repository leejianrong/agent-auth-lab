# ADR-0001: Use Python/FastAPI for every lab backend, Svelte+Vite for every frontend

- Status: Accepted
- Date: 2026-08-19
- Deciders: user, agent (F1)

## Context

Every lab needs a backend that can issue/verify sessions and JWTs, run OAuth2/
OIDC flows, and eventually host agent identities and a policy evaluator, plus
a small frontend for the observable UI affordances (cookie inspector, JWT
decoder, approval queue, trace dashboard). The stack choice is the single most
expensive decision to reverse — it touches every line of starter and solution
code across all 14 labs — so it was escalated as a fork rather than assumed.

## Decision

All backend code across all 14 labs is Python using FastAPI. All frontend UI
is Svelte with Vite as the build tool. This is a fixed pair for the whole
course; individual labs don't get to pick a different stack.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Node.js/TypeScript + Express/Fastify | Was the agent's initial recommendation (deepest OAuth/JWT ecosystem); user has an explicit Python preference |
| Django (Python) | Heavier and more opinionated than the course needs; FastAPI's explicit dependency-injection style makes authn/authz middleware more visible to a learner, which is the pedagogical point |
| React or plain HTML/htmx for the frontend | User explicitly requested Svelte + Vite when a frontend is needed |

## Consequences

- All JWT/OAuth/session libraries, examples, and error messages in every
  handout are Python-specific (`python-jose`/`pyjwt`, `passlib`/`argon2-cffi`,
  FastAPI's `Depends()` for auth middleware).
- Two toolchains to install per lab (Python + Node for the frontend) whenever
  a lab has a UI affordance — acceptable since most labs need a UI anyway for
  the observable-outcome requirement (R1).
- The shared observability harness (ADR-0006) must expose both a Python-
  importable library and a small Svelte dashboard component, since every lab
  reuses it.
- Locks the course out of Node-specific agent tooling (e.g. LangChain.js)
  without a Python-side equivalent; the optional real-LLM stretch path
  (ADR-0005) talks to any OpenAI-compatible API (e.g. OpenRouter) via the
  standard Python `openai` client, which is first-class, so this isn't a
  real constraint in practice.
