# ADR-0003: One continuously-growing capstone system, not 14 standalone projects

- Status: Accepted
- Date: 2026-08-19
- Deciders: agent (assumed, load-bearing)

## Context

The user's stated end goal is that by the final labs, the learner is "dealing
with a whole system we built by ourselves, with agents running around doing
tasks." That only works if each lab's solution is the next lab's starting
point — otherwise the course is 14 disconnected demos and the capstone feel
never happens. This needs to be decided before any repo scaffolding exists,
since it drives the directory layout and how starter code gets produced.

## Decision

Single monorepo. `/labs/lab-NN-slug/{starter,solution}` per lab. Each lab's
`solution/` is the complete, working system through that lab's concept; the
*next* lab's `starter/` is generated from it — a scripted diff that
reintroduces TODOs/stub files for the new concept being taught, rather than a
hand-maintained parallel copy. `/shared/observability-harness` is a separate
package imported by every lab's solution and starter, not duplicated per lab.

## Alternatives considered

| Option | Why not |
|--------|---------|
| 14 independent standalone mini-projects | Simpler to build in isolation, but directly contradicts the requested capstone arc — a learner would never experience "the whole system," only isolated concepts |
| Hand-maintained starter/solution pairs per lab (no scripted generation) | Guarantees drift the moment a mid-course lab's solution is patched after the fact — the starter for the next lab silently goes stale |
| One shared branch per lab in a single package (no starter/solution folder split) | Harder for a learner to diff "what did I need to add" against a clean reference, and harder for course maintainers to keep a lab's starter buildable in isolation |

## Consequences

- Buys the capstone experience the whole course is designed around, and a
  single place (`/shared/observability-harness`) to fix or improve the
  dashboard/audit-log tooling once, benefiting all 14 labs at once.
- Costs: the scripted solution→starter generator is itself a piece of
  infrastructure that has to work correctly and needs its own light testing;
  if it breaks for a given lab, that lab's starter must be hand-patched,
  which can drift (flagged as an open risk in PLAN.md, first tested in
  Slice 1 / lab 00).
- Forecloses labs being freely reordered or skipped — the course is
  necessarily sequential, which matches the "incremental" requirement (R0)
  but means a learner can't jump straight to, say, lab 09 without having
  built the system underneath it.
- Requires every lab's `solution/` to remain in a runnable, demoable state
  forever, since it's load-bearing infrastructure for every subsequent lab,
  not just a reference answer key.
