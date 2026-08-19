# ADR-0004: Build a teaching-grade OIDC/OAuth2 IdP from scratch instead of integrating a real vendor

- Status: Accepted
- Date: 2026-08-19
- Deciders: agent (assumed, Q8)

## Context

Lab 04 teaches OAuth2/OIDC. The learner could either stand up a real identity
provider (Keycloak, Auth0, Okta, Ory) and integrate against it, or build a
minimal IdP themselves as part of the lab. Real vendors are what a working
developer will actually use day to day, but this course exists specifically
to teach fundamentals by building — the whole pedagogical model (per PLAN.md
Solution) is "prove it by building it," not "configure a vendor console."

## Decision

Lab 04 has the learner build a minimal "Lab IdP": authorization code flow
with PKCE, client-credentials flow, token introspection, and revocation —
just enough surface to drive every later lab. It is explicitly not
spec-complete and explicitly not for production use. Real vendors (Keycloak
named specifically) are mentioned only as further-reading pointers in the
lab 04 handout, not integrated.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Integrate Keycloak via docker-compose | More realistic ("how production actually does it"), but turns lab 04 into a configuration exercise rather than a build exercise, and the learner never sees what's inside the token issuance/validation logic they'd otherwise be trusting a vendor for |
| Integrate a hosted SaaS IdP (Auth0/Okta) | Requires a third-party account and network dependency for a self-paced offline-friendly course, and hides the exact mechanics (PKCE, code exchange) this lab exists to teach |

## Consequences

- Learner comes away understanding OIDC/OAuth2 internals deeply enough to
  debug a real vendor's behavior later, which is the actual point of a
  fundamentals course.
- The Lab IdP must be clearly and repeatedly labeled as non-production in the
  handout and code comments — shipping something that merely *looks* like a
  real IdP is a genuine risk if a reader lifts it verbatim (see ADR-0008).
- If it later turns out learners need hands-on experience with a real
  vendor's admin console specifically (a different, legitimate skill), that
  would need a new lab — this default is recorded as reversible-but-costly in
  PLAN.md (Q8).
