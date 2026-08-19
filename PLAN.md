# Agent Auth Lab: Plan

Status: agreed · Milestone: v1 (all 14 labs + docs site)

## Problem

Junior developers learn authentication and authorization piecemeal — a Stack
Overflow answer for JWT here, a copy-pasted OAuth snippet there — without ever
building the mechanisms themselves or seeing *why* each one exists. That gap is
getting worse, not better: the same developers are now expected to reason about
identity for autonomous agents (service accounts that act without a human in
the loop, delegated "on behalf of" calls, agent-to-agent requests), a topic
almost no existing course or tutorial covers with any rigor.

There is no single, hands-on, incrementally-structured resource that takes a
learner from "what is a session cookie" to "how do I stop one agent
impersonating another" inside one continuously-growing codebase, with every
concept demonstrated by something they can watch happen — a UI panel, a denied
request, a trace.

## Solution

A free, self-paced course: **14 labs (00–13)**, each a university-style lab
handout (objectives, background, step-by-step build instructions, a "you're
done when" checklist, and open-ended extension questions), published as a
Zensical docs site on GitHub Pages.

The learner isn't reading about auth — they're building one continuously
growing system. Lab 0's solution becomes lab 1's starting point, and so on
through lab 13, where they extend a working platform that has human users,
service accounts, and multiple autonomous agents, all authenticated and
authorized correctly, with every decision visible in a live dashboard.

Every lab produces something observable: a cookie inspector, a live JWT
decoder, an audit log entry, a denied request, a trace showing an agent's
delegated identity flowing through three hops. Concepts are proven by making
them fail first (session hijacking, a privilege-escalation bug, a confused
deputy exploit) and then fixed.

## Users and actors

- **Primary: the learner** — a junior software developer, working solo,
  self-paced, on their own machine. No cohort, no instructor, no grading.
- **Secondary (fictional, in-system): humans, service accounts, and agents**
  inside the capstone application the learner builds. These are pedagogical
  constructs the learner creates and controls, not independent real
  stakeholders — there's no conflict to arbitrate since one learner drives
  everything.

## Scope

**In this milestone.**

- 14 lab handouts (00–13) per the syllabus in [Shape](#shape), each with a
  starter scaffold and a full reference solution.
- One continuously-growing capstone codebase: Python/FastAPI backend +
  Svelte/Vite frontend, SQLite-backed, that the labs build up in sequence.
- A pre-built, shared observability harness (structured audit log + trace IDs
  + a lightweight web dashboard) that learners consume, not build.
- A self-built teaching-grade OIDC/OAuth2 "Lab IdP," introduced in lab 04 and
  reused through the rest of the course.
- Deterministic scripted agents as the default "agent" implementation for
  labs 07–13, runnable with zero external dependencies or API cost.
- An optional stretch path wiring a real LLM-backed agent — via any
  OpenAI-compatible API (e.g. OpenRouter) — into the same interface, for
  learners who want it — never required to finish a lab.
- A Zensical docs site, auto-built and deployed to GitHub Pages via GitHub
  Actions on every push to the docs source.
- Self-check test suites (pytest) per lab where the behavior is a concrete
  backend assertion (401 on expired JWT, audit log entry produced, etc.).

**Out.**

- A production-hardened IdP. The Lab IdP is intentionally minimal — good for
  teaching internals, not for anyone to actually deploy. Called out explicitly
  in the lab 04 handout.
- WebAuthn/passkeys/biometric auth. A large enough topic to deserve its own
  lab, but adding it would push the course past 14 labs; noted as a future
  addition, not this milestone.
- Mobile/native app auth flows (App Links, native OAuth redirects, keychain
  storage). Web-only for this course.
- Integrating a real third-party IdP (Keycloak, Auth0, Okta). We build our
  own; vendors are mentioned only as "how it's done in production" reading
  pointers (see ADR-0004).
- Identity governance / access certification (the SailPoint-style "who should
  still have this access" discipline). Mentioned once, in the capstone
  handout, as an adjacent field — no governance workflow gets built.
- Autograding infrastructure. Self-check test suites exist for the learner's
  own benefit; nothing is submitted or scored.
- Cloud deployment of the lab applications themselves. Everything the learner
  builds runs locally (optionally under docker-compose from lab 06 on); only
  the docs site is deployed anywhere.
- Concurrency correctness under simultaneous writes. Not a concept this course
  teaches; last-write-wins is fine everywhere it comes up.
- Versioning/migration of course content across future spec revisions
  (e.g. a future OAuth RFC update). Single version for v1.

## Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| R0 | Learner works through 14 sequential labs — handout, starter, solution — building one continuously-growing system from traditional web auth to multi-agent authz | Core goal |
| R1 | Every lab produces an observable outcome (UI panel and/or structured audit/trace log) showing the concept working — and failing/being denied — live | Must-have |
| R2 | Labs 00–03 teach traditional authn/authz (sessions, JWT, RBAC, ABAC/ReBAC) with no agents involved | Must-have |
| R3 | Labs 04–06 teach federated & delegated identity (OIDC, OAuth scopes/consent, service-to-service authn) | Must-have |
| R4 | Labs 07–13 introduce autonomous agents as first-class identities: scoped tools, delegated on-behalf-of authority, human-in-the-loop approval, multi-agent authz, centralized audit/revocation, open-ended capstone | Must-have |
| R5 | Docs are published as a Zensical site on GitHub Pages, built via GitHub Actions from Markdown handouts | Must-have |
| R6 | Each lab ships a "starter" scaffold (TODOs) and a full "solution," both runnable locally with one documented command | Must-have |
| R7 | Real LLM-driven agents (via any OpenAI-compatible API, e.g. OpenRouter) are supported as an optional stretch path, never required to complete a lab | Nice-to-have |
| R8 | Every lab handout closes with open-ended extension questions | Must-have |

## Shape

| Part | Mechanism | ADR |
|------|-----------|-----|
| S1 | Monorepo: `/labs/lab-NN-slug/{starter,solution}`, `/shared/observability-harness`, `/docs` (Zensical source under a non-colliding subpath). Solution(N) is the basis starter(N+1) is generated from. | ADR-0003 |
| S2 | FastAPI backend + Svelte/Vite frontend per lab, SQLite-backed storage throughout | ADR-0001, ADR-0002 |
| S3 | Self-built mini OIDC/OAuth2 IdP, introduced lab 04, reused and extended through lab 13 | ADR-0004 |
| S4 | Pre-built observability harness: structured JSON audit log, OTel-shaped trace IDs, lightweight dashboard UI — imported by every lab, not built by the learner | ADR-0006 |
| S5 | Deterministic scripted agent runner as the default agent implementation, with an OpenAI-compatible-API-backed adapter (e.g. OpenRouter) behind the same interface as an opt-in swap | ADR-0005 |
| S6 | Hybrid policy evaluation: hand-rolled rule engine in labs 02–03, OPA sidecar introduced lab 08+ once agent scoping needs production-grade policy language | ADR-0007 |
| S7 | Zensical docs site, GitHub Actions → GitHub Pages deploy | ADR-0009 |
| S8 | docker-compose introduced from lab 06 onward (once multiple services run concurrently); every service remains runnable standalone via `uvicorn`/`npm run dev` for learners who prefer that | — |

## Affordances

**UI.**

| Affordance | Place | Wires to |
|------------|-------|----------|
| Login form, cookie/session inspector | Lab 00 UI | Session store |
| Live JWT decoder (claims + signature validity) | Lab 01 UI | Token verify endpoint |
| Role-gated admin panel, allow/deny audit view | Lab 02 UI | RBAC middleware, audit log |
| Policy-decision trace viewer ("which rule fired") | Lab 03 UI | Policy evaluator |
| OAuth/OIDC redirect + token-exchange live trace | Lab 04 UI | Lab IdP |
| Consent screen, scope/token introspection panel | Lab 05 UI | Consent + introspection endpoints |
| Agent activity dashboard | Lab 07+ UI | Observability harness |
| Pending-approval queue, approve/deny controls | Lab 10 UI | Approval-gate service |
| Unified cross-identity trace dashboard, revocation kill-switch | Lab 12 UI | Observability harness, revocation endpoint |

**Non-UI.**

| Affordance | Kind | Wires to |
|------------|------|----------|
| REST/JSON API per service | HTTP handler | FastAPI routers |
| Structured audit log + trace-ID propagation | Shared library | Observability harness |
| Scripted agent runner / OpenAI-compatible-API adapter | CLI/service | Agent identity + scoped token |
| Policy evaluator (hand-rolled, then OPA) | Service/sidecar | Authz decision points |
| pytest self-check suite | Test command | Learner's own starter implementation |

## Implementation decisions

- Password hashing via `passlib`/`argon2-cffi`; JWTs via `python-jose` or
  `pyjwt` (final pick made when lab 00/01 code is written, not architectural).
- Sessions: server-side store in SQLite, cookie carries only an opaque session
  ID — deliberately contrasted with the stateless JWT approach in lab 01.
- The Lab IdP (ADR-0004) implements just enough of OIDC/OAuth2 (authorization
  code + PKCE, client-credentials, token introspection, revocation) to drive
  every later lab — not a spec-complete implementation.
- Agent identity is a first-class row type distinct from human users, each
  with its own client credentials and scoped token issuance path — this
  distinction is what makes labs 07–11 possible.
- The observability harness assigns every request a trace ID at the edge and
  propagates it through internal calls (including agent → agent hops), so
  lab 12's "unified trace across human/service/agent identities" has
  something real to unify.
- Starter packs are generated from each lab's solution by a scripted diff
  (reintroduce TODOs/stubs for the new concept), not hand-maintained in
  parallel — see ADR-0003 consequences.
- Zensical content source lives at `docs/course/` (not bare `docs/`), so it
  never collides with `docs/adr/` or this plan's own files at the repo root.
- Intentionally-vulnerable "before" code (lab 00's plaintext passwords, lab
  02's privilege-escalation bug, lab 11's confused-deputy exploit) is clearly
  labeled, kept out of any deployed environment, and never wired to a real
  network or real credentials — see ADR-0008.

## External dependencies

| Dependency | License | Offline? | Fallback if unavailable |
|------------|---------|----------|--------------------------|
| Python, FastAPI, `pyjwt`/`python-jose`, `passlib`/`argon2-cffi` | MIT/BSD-family | Yes | None needed — core to the course, no substitute |
| Svelte + Vite | MIT | Yes | None needed — core to the course |
| SQLite | Public domain | Yes | None needed |
| OPA (Open Policy Agent), introduced lab 08+ | Apache 2.0 | Yes — runs as a local binary, no network call | If too heavy for the target audience, lab 08 falls back to an extended hand-rolled evaluator (ADR-0007) |
| `openai` Python client, pointed at an OpenAI-compatible endpoint (e.g. OpenRouter), optional stretch path only (labs 07+) | Apache 2.0 (SDK) | No — real API calls, costs money, requires network | Entirely optional; every lab is fully completable and self-checkable with the scripted agent only (ADR-0005) |
| Zensical | Static-site generator; build is local/offline | Yes to build; GitHub Actions + Pages needed only to publish | If GitHub Actions is unavailable, the site can still be built and viewed locally |
| Docker / docker-compose, lab 06+ | Apache 2.0 (Docker Engine) | Yes | Each service remains runnable standalone via `uvicorn`/`npm run dev` without Docker |

## Testing approach

Two seams per lab, no more:

- **Learner-facing self-check (pytest):** the concrete, checkable backend
  behaviors — expired JWT → 401, wrong role → 403 with an audit log entry,
  revoked token rejected within one request cycle. Runs against the learner's
  own starter implementation for immediate feedback.
- **Manual/visual demo:** anything the observable outcome is a UI (cookie
  inspector, trace dashboard, approval queue) — the handout states exactly
  what to click and what you should see.

Course-maintainer testing (browser automation, cross-lab regression) is a
publishing-time concern for whoever maintains the course, not a learner-facing
feature, and isn't built as part of this milestone.

## Assumed defaults

| ID | Assumed | Cost if wrong |
|----|---------|---------------|
| Q6 | Solo self-paced learner, no cohort/grading | Low — no infra was built around a cohort model to unwind |
| Q7 | SQLite as the only datastore, across every lab | Medium — a lab needing real concurrent writes would need a rewrite of its storage layer |
| Q8 | Self-built Lab IdP instead of a real vendor IdP | Medium — would need a new lab 04 if a real-vendor integration turns out to matter more than internals |
| Q9 | Intentionally-vulnerable code is safe because it never runs outside the learner's machine | High if violated — must stay true, hence ADR-0008 |
| Q10 | No autograding; self-check pytest suites are advisory only | Low — grading could be layered on top later without changing lab content |
| Q11 | docker-compose only from lab 06 onward, optional before that | Low — earlier labs are single-service, no real cost either way |
| Q12 | Single content version, no migration plan for spec updates | Low for v1; revisit if the course gets a v2 |

## Open risks

- **Starter-pack generation drift** (S1/ADR-0003): if the scripted
  solution→starter diff doesn't handle a lab cleanly, that lab's starter must
  be hand-patched, which can silently diverge from its solution over time.
  Slice 1 (lab 00) is where this gets proven or disproven first.
- **OPA integration friction** (S6/ADR-0007): introducing OPA at lab 08 mid-
  course is a bigger jump than staying hand-rolled throughout. If it proves
  too heavy for the target audience, lab 08 may need to fall back to an
  enhanced hand-rolled evaluator. Revealed in the slice that builds lab 08.
- **Confused-deputy exploit realism** (lab 11): a contrived exploit that
  doesn't feel like a real vulnerability undermines the whole lab. Revealed
  when that slice's demo is built and reviewed.
