# Agent Auth Lab

A 14-lab (00–13), hands-on course teaching authentication and authorization
— starting from traditional web auth (sessions, JWT, RBAC/ABAC), through
federated identity (OIDC/OAuth2), to authn/authz for autonomous agents
(scoped tool tokens, delegated on-behalf-of authority, human-in-the-loop
approval, multi-agent authz, unified audit/revocation). Labs build one
continuously-growing capstone system rather than 14 disconnected demos: each
lab's `solution/` is the next lab's `starter/`.

Read `PLAN.md` first — problem, scope, requirements, shape. Then
`docs/adr/*` for why each architectural decision was made, and `SLICES.md`
for the build plan. `QUESTIONS.md` is the decision register (what's decided,
what's assumed, what's deferred).

## Repo layout

- `PLAN.md`, `SLICES.md`, `QUESTIONS.md` — planning artifacts, repo root.
- `docs/adr/` — architectural decision records.
- `docs/course/` — Zensical source for the published lab handouts (deployed
  to GitHub Pages via GitHub Actions). Keep this distinct from `docs/adr/`.
- `labs/lab-NN-slug/{starter,solution}` — per lab. `starter/` is generated
  from the previous lab's `solution/` via a scripted diff (ADR-0003); don't
  hand-maintain it in parallel.
- `shared/observability-harness/` — the pre-built audit-log + trace-ID +
  dashboard package every lab imports. Learners consume this, they don't
  build it.

## Stack conventions

- Backend: Python 3.12 + FastAPI, everywhere (ADR-0001). Use `python3.12` /
  `uv venv --python 3.12` when creating a lab's virtualenv — not 3.11, not
  whatever `python3` happens to resolve to on the machine.
- Frontend: Svelte + Vite, wherever a lab needs a UI (ADR-0001).
- Storage: SQLite only, no other database (ADR-0002).
- Agents (labs 07+): deterministic scripted runner by default. The optional
  real-LLM stretch path talks to any OpenAI-compatible API (e.g. OpenRouter)
  via the standard `openai` client with a configurable base URL/model —
  never pin this to one model vendor's SDK (ADR-0005).
- Policy: hand-rolled rule evaluator in labs 02–03, OPA introduced lab 08+
  (ADR-0007).
- Intentionally-vulnerable "before" code (session hijacking, privilege
  escalation, confused deputy) must stay labeled, localhost-only, and always
  paired with the fix in the same lab (ADR-0008).

## Writing conventions

- **Always invoke the `/natural-writing` skill before drafting or editing
  any prose document in this repo** — lab handouts, `PLAN.md`, ADRs,
  READMEs, everything. This matters most for learner-facing material
  (`docs/course/**`): those are read by a junior developer trying to learn,
  not skimmed by an engineer who already knows the domain, so stiff or
  visibly AI-flavored prose costs the most there.
- Lab handouts follow the university-lab-handout shape: objectives,
  background/concepts, step-by-step build instructions, a concrete
  "you're done when" checklist, then open-ended extension questions.
- Every lab's observable outcome (a UI panel, a denied request, a trace)
  should be named explicitly in its handout — this course teaches by
  watching something happen, not by reading about it.
