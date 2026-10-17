# Agent Auth Lab

A 14-lab (00–13), hands-on course teaching authentication and authorization,
starting from traditional web auth (sessions, JWT, RBAC/ABAC), through
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
- Frontend: Svelte + Vite + TypeScript, wherever a lab needs a UI (ADR-0001).
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

- **Always invoke `/natural-writing` before drafting or editing any prose
  document in this repo** — lab handouts, `PLAN.md`, ADRs, READMEs,
  everything. That includes the prose inside handout components: stepper
  `.flow` text, predict-then-reveal folds, widget copy, and the going-further
  discussions. Tutorials are the case where stiff, machine-flavoured writing
  costs the most.
- **Writing or editing a lab handout specifically? Invoke the
  `write-lab-handout` project skill.** It covers handout structure (closing
  the loop on the previous lab before introducing the next one), the
  no-spoilers rule, and diagram requirements (ADR-0010).
- Every handout (labs 00-13) uses the engagement components in ADR-0011
  (generated steppers, predict-then-reveal folds, per-arc widgets, folded
  previous-lab walkthrough). Stepper sources live in `docs/course/flows/`,
  widgets in `docs/course/widgets/`. The `write-lab-handout` skill has the how.
- Handout code excerpts are extracted from the real starter/solution file
  (strip the `LAB:` markers), never retyped. The current lab's sections show
  the starter side only. Check built HTML for solution-only lines before merging.
- A handout's "run it" steps run against the **starter**, so they must describe
  what the starter does (usually the bug), not the fixed behaviour.
- Every lab's observable outcome (a UI panel, a denied request, a trace)
  should be named explicitly in its handout — this course teaches by
  watching something happen, not by reading about it.

## PR review conventions

- **Reviewing a PR uses at most one subagent.** A single subagent (or the
  orchestrator's own manual read of `gh pr diff`) is enough to vet a lab PR
  — don't invoke fan-out/multi-agent review workflows (e.g. the
  `code-review` skill's dimension-fan-out-plus-adversarial-verify mode, or
  the `Workflow` tool) against a PR in this repo. Those are built for
  large, uncertain changes; a lab PR is small and scoped enough that one
  reviewer pass is sufficient, and the fan-out burns a disproportionate
  number of agents and tokens for what it finds.

## Commands that aren't obvious

- Regenerate a lab's starter after editing its solution:
  `python3 scripts/generate_starter.py labs/lab-NN-slug` (add `--check` to
  verify). CI fails on a stale starter.
- Regenerate a handout's stepper blocks:
  `python3 scripts/stepper_gen.py --inject docs/course/lab-NN-slug.md`
  (`--check` in CI). Never hand-write stepper SVG.
- Docs build: `make docs-build` (`zensical build --clean --strict`) must be
  clean. Zensical is not in any lab venv; the Makefile installs it into
  `.docs-venv`. `make stepper-check` verifies every generated stepper.
- Screenshots and browser checks use Playwright installed in a scratch dir,
  never the repo. Ports 8000, 5173, 9000 and 8181 must be free first; free them
  with `ss -ltnp` and `kill -9 <pid>`, never `pkill -f`. Delete `*.db*`, `*.pem`
  and `dist` before running `generate_starter.py` or committing, since the
  generator copies them.
- Merge PRs once CI is green. Don't commit unrelated working-tree files
  (check `git status` first).
