# ADR-0005: Deterministic scripted agents by default; real LLM agents optional

- Status: Accepted
- Date: 2026-08-19
- Deciders: user, agent (F2)

## Context

Labs 07–13 need "agents" that act as autonomous callers with their own
identity. These could be real LLM-driven agents (via any OpenAI-compatible
API, e.g. OpenRouter, which fronts many providers behind one interface) or
fully deterministic scripted bots that follow fixed logic. The choice affects
whether every learner needs an API key and incurs cost, and whether a lab's
"you're done when" checklist can be a precise, deterministic assertion or has
to tolerate LLM non-determinism.

## Decision

The default "agent" in every lab from 07 onward is a small deterministic
scripted program (fixed logic, no model call) that acts against the capstone
API using its own service identity and tokens. A separate adapter, behind the
same interface, optionally swaps in a real LLM-powered agent — talking to
any OpenAI-compatible endpoint (e.g. OpenRouter, or a self-hosted
OpenAI-compatible server) via the standard `openai` Python client with a
configurable base URL and model name — for learners who want to see the real
thing. This is clearly marked as a stretch path, never required to complete
a lab or pass its self-check tests, and never pins the course to one model
vendor.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Real LLM-powered agents as the default | Requires every learner to hold an API key and pay to run the course; introduces non-determinism into what should be crisp, checkable "you're done when" assertions (R1) |
| No LLM option at all | Misses a real opportunity — this course is specifically about *agentic* authn/authz, and learners interested enough to take it will likely want to see a real model-driven agent hit the same guardrails at least once |
| Pin the optional path to one specific model provider's SDK | Locks the course to that vendor's pricing/availability/API shape for a part of the course that's supposed to be a flexible, learner's-choice extra; an OpenAI-compatible interface lets a learner point at whichever provider (or local model server) they already have access to |

## Consequences

- Every agent lab is free and reproducible to complete by default — no cost,
  no flakiness, no dependency on any external model API's availability.
- The agent-identity and scoped-token machinery (client credentials, capability
  tokens, on-behalf-of claims) has to be designed against a stable interface
  that both a scripted runner and a real LLM call can sit behind — a small
  extra design constraint on lab 07's scaffolding, but a cheap one.
- The optional adapter's only requirement is an OpenAI-compatible base URL,
  API key, and model name in `.env` — a learner can point it at OpenRouter,
  another compatible provider, or a locally-hosted OpenAI-compatible server
  without any code changes.
- Learners who skip the optional stretch path never see a real LLM agent
  attempt (and get denied for) an out-of-scope tool call — that experience is
  strictly bonus, not core.
