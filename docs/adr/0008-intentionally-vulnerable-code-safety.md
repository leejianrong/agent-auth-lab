# ADR-0008: Intentionally-vulnerable pedagogical code stays labeled, offline, and un-forkable-as-real

- Status: Accepted
- Date: 2026-08-19
- Deciders: agent (assumed, load-bearing)

## Context

Several labs are only effective if the learner first sees the *broken*
version fail: lab 00's plaintext-password start, lab 02's privilege-
escalation bug, lab 11's confused-deputy exploit. That means this public,
open-source course necessarily contains working exploit code and
intentionally-insecure "before" states. Left unaddressed, a reader could
mistake the vulnerable starting point for a real recommendation, or a learner
could unknowingly deploy it somewhere reachable.

## Decision

Every intentionally-vulnerable "before" state is (a) clearly labeled in the
handout and in a code comment at the point of vulnerability, (b) never
wired to a real network, real credentials, or any deployment target more
public than the learner's own machine/localhost, and (c) always paired, in
the same lab, with the fixed version and an explanation of why the fix
matters. Secrets used anywhere in the course (e.g. an OpenAI-compatible API
key for the optional stretch path) are handled via `.env` + `.gitignore`, never
committed, with an explicit callout in any lab that touches them.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Skip showing the actual vulnerable code, describe it only in prose | Weaker pedagogy — the whole course thesis is "prove it by building it," and that applies to seeing a real bug fail before fixing it, not just reading about it |
| Rely on learners to intuit safety practices without explicit callouts | Not something to assume of a junior audience; a security course teaching bad security hygiene about its own vulnerable code would be a real credibility problem |

## Consequences

- Costs a bit of handout real estate in every lab that has a "before" state,
  for the explicit safety callout — worth it.
- No lab may ever suggest running the vulnerable "before" state anywhere but
  localhost/the learner's own machine — this constrains any future addition
  of a hosted/cloud demo mode for the course.
- Keeps the course itself from becoming a liability if code is copy-pasted
  out of context (the labeling and localized comments are the mitigation).
