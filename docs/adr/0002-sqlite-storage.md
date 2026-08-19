# ADR-0002: SQLite as the only datastore across every lab

- Status: Accepted
- Date: 2026-08-19
- Deciders: agent (assumed, Q7)

## Context

The capstone system needs to persist users, agents, tokens, policies, audit
events, and approval requests, growing across 14 labs. The learner is a
self-paced junior developer working alone on their own machine — anything
requiring a separately-running database server is friction the course doesn't
need, and part of the point (R1: observable outcomes) is that a learner can
literally open the database file and see what changed after an action.

## Decision

Every lab's capstone backend persists to a single SQLite file. No lab
introduces Postgres, MySQL, or a managed cloud database.

## Alternatives considered

| Option | Why not |
|--------|---------|
| PostgreSQL via docker-compose | Real-world realism, but adds an always-running service and connection config for zero pedagogical benefit before lab 06 (when docker-compose gets introduced anyway for multi-service labs) |
| In-memory only (no persistence) | Can't demonstrate revocation, audit history, or session persistence across restarts, which several labs need |

## Consequences

- Learners can inspect the raw `.db` file with any SQLite browser as part of
  a lab's "you're done when" check — a concrete, free debugging affordance.
- No concurrent-write story is needed (out of scope, per PLAN.md) — SQLite's
  single-writer model is a non-issue for a solo learner driving one browser
  tab and a handful of scripted agents.
- If a future lab ever needed genuine concurrent multi-writer behavior, this
  would need to change; PLAN.md flags that as the cost if this default is
  wrong (Q7).
