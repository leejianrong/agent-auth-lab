# ADR-0009: Zensical docs site, deployed to GitHub Pages via GitHub Actions, sourced from docs/course/

- Status: Accepted
- Date: 2026-08-19
- Deciders: user, agent

## Context

The 14 lab handouts need to be published somewhere a learner can read them
without cloning the repo, per the user's original ask ("a zensical page
deployed on github pages"). The planning artifacts for this project already
occupy `docs/adr/` and `docs/` at the repo root (PLAN.md, SLICES.md,
QUESTIONS.md live at repo root per this skill's convention since `docs/`
didn't exist yet when planning started) — the Zensical site's own content
source needs a home that doesn't collide with those.

## Decision

Zensical content source lives at `docs/course/`, with Zensical's config at
the repo root pointing at it. A GitHub Actions workflow builds the site on
push to the main branch and deploys the build output to GitHub Pages.

## Alternatives considered

| Option | Why not |
|--------|---------|
| mkdocs-material | Very similar feature set, but the user specifically asked for Zensical |
| Docusaurus | React-based; adds a third frontend toolchain to the project alongside the Svelte lab UIs, for no benefit over Zensical |
| Content source at bare `docs/` | Collides with `docs/adr/` (planning ADRs) and this project's own PLAN.md/SLICES.md/QUESTIONS.md sitting at repo root — keeping course content at `docs/course/` avoids ambiguity between "planning docs" and "published course content" |

## Consequences

- One more path convention to keep straight (`docs/adr/` = planning ADRs,
  `docs/course/` = published lab handouts, repo root = PLAN/SLICES/QUESTIONS)
  — documented here so it doesn't get relitigated later.
- Deploy is fully automated; publishing a new/edited lab handout is a normal
  commit to `docs/course/`, no manual build step.
- Site content and lab code (`/labs/...`) live in the same repo, so a single
  PR can update a handout and its corresponding starter/solution together —
  intentional, since drift between the two is a real risk otherwise.
