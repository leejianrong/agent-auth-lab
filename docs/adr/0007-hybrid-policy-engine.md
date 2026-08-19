# ADR-0007: Hand-rolled policy evaluator early, introduce OPA once agent scoping needs it

- Status: Accepted
- Date: 2026-08-19
- Deciders: user, agent (F4)

## Context

Labs 02–03 teach RBAC then ABAC/ReBAC; labs 08+ need finer-grained,
composable policy for scoped agent tool permissions and multi-agent authz.
A single policy tool could be used throughout (either hand-rolled the whole
way, or a real policy engine like OPA from the start), or the course could
switch tools partway once the teaching need changes.

## Decision

Labs 02–03 use a small hand-rolled rule evaluator the learner builds
themselves, so the *mechanics* of an authz decision (subject, resource,
action, attributes in, allow/deny out) are transparent and owned. Starting
around lab 08, the course introduces OPA (Open Policy Agent) as a sidecar,
framed explicitly as "here's the real-world tool that does what you just
built, at production scale," once agent tool-scoping policy gets complex
enough to benefit from a real policy language (Rego).

## Alternatives considered

| Option | Why not |
|--------|---------|
| Hand-rolled evaluator for the entire course | Simpler throughout, but never shows the learner the industry-standard tool they'll actually meet at a job; also doesn't scale well to the compositional scoping needed for lab 11's multi-agent policy |
| OPA (or Casbin) from lab 02 onward | More realistic sooner, but adds a new binary/config language before the learner has even built RBAC by hand — steeper ramp for zero pedagogical gain that early |

## Consequences

- Learners understand the mechanics before being handed a production tool,
  which matches the course's build-first philosophy.
- Introduces a real external dependency (the OPA binary, and Rego as a new
  small language to learn) partway through the course — a genuine jump in
  complexity at lab 08, flagged as an open risk in PLAN.md.
- If OPA proves too heavy for the target audience at that point, lab 08
  falls back to an extended hand-rolled evaluator instead — a decision
  deferred to when that slice is actually built and reviewed.
