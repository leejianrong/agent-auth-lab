# Agent Auth Lab: Slices

Vertical increments of *building the course itself*. Each ends in something
demonstrable: a lab a real learner could sit down and complete. Slice 1
confronts the riskiest unknown — whether the whole toolchain pattern (monorepo
layout, starter/solution generation, shared observability harness, docs
deploy) actually holds together — before it gets committed to 13 more times.

## V1: Course scaffolding + Lab 00 (Sessions & Cookies)

**Delivers:** R0 (partial — pattern proven), R1, R2 (partial — lab 00 only),
R5, R6

**Build plan**

1. Scaffold the monorepo: `/labs/`, `/shared/observability-harness/`,
   `docs/adr/` (exists), `docs/course/`.
2. Build `/shared/observability-harness` v1: structured JSON audit log,
   trace-ID helper, minimal Svelte dashboard component that renders a log
   stream.
3. Build `labs/lab-00-sessions-cookies/solution`: FastAPI backend with
   plaintext-password login (intentionally vulnerable, per ADR-0008),
   SQLite-backed session store, cookie-based auth; Svelte frontend with a
   login form and a cookie/session inspector panel; wired to the
   observability harness.
4. Fix the vulnerability in the same lab (hash passwords, rotate session
   IDs on login) and demonstrate the before/after in the handout.
5. Write the scripted solution→starter generator and run it once to produce
   `labs/lab-00-sessions-cookies/starter` — this is the riskiest step, and
   the one Slice 1 exists to prove out.
6. Write the lab 00 handout in `docs/course/`, including the "you're done
   when" checklist and open-ended questions.
7. Stand up the Zensical site (config at repo root, content in
   `docs/course/`) and the GitHub Actions deploy workflow; confirm it
   publishes to GitHub Pages.
8. Write the pytest self-check suite for lab 00 (session-fixation resistance,
   rejected bad credentials, audit log entry produced on login).

**Demo:** clone the repo, run lab 00's starter, hit the login form with the
provided broken and then fixed implementations, watch the cookie/session
inspector and audit log update live; run the pytest self-check against a
completed starter and see it pass; visit the deployed GitHub Pages URL and
see the lab 00 handout rendered.

**Rests on assumptions:** Q7 (SQLite everywhere) and Q9 (vulnerable code is
safe because it's local-only) — if either is wrong, this slice is where it
would first surface.

### Test plan

#### End-to-end

- A learner following the lab 00 handout from a fresh starter checkout ends
  with a passing pytest self-check and a working login flow.
- The deployed GitHub Pages site renders the lab 00 handout with working
  navigation.

#### Integration

- Login with the vulnerable ("before") implementation succeeds but the
  audit log flags the plaintext-password path.
- Login with the fixed implementation hashes correctly and rejects a
  tampered session cookie.
- The solution→starter generator, run against lab 00's solution, produces a
  starter that builds and runs (even though incomplete).

#### Unit

- Password hashing round-trips correctly.
- Session ID rotates on successful login.
- Audit log entry schema validates for a login event.

## V2: Arc 1 remainder — Labs 01–03 (JWT, RBAC, ABAC/ReBAC)

**Delivers:** R2 (complete), R1, R6, R8

**Build plan**

1. Lab 01: extend the capstone with JWT issuance/verification alongside
   sessions; build the live JWT decoder UI; demonstrate signature tampering
   and expiry both failing correctly.
2. Lab 02: add roles and an RBAC middleware layer; build the admin panel;
   seed a real privilege-escalation bug, then fix it, both visible in the
   audit log.
3. Lab 03: add the hand-rolled ABAC/ReBAC rule evaluator (ADR-0007) and a
   policy-decision trace viewer showing which rule fired.
4. Run the solution→starter generator for each of the three labs.
5. Write all three handouts, self-check suites, and extension questions.

**Demo:** starting from lab 00's solution, build through lab 03; an admin
panel is role-gated, a non-owner is denied access to another user's resource
with the exact policy rule shown in the trace viewer.

**Rests on assumptions:** none new — reuses the pattern Slice 1 proved.

### Test plan

#### End-to-end

- A learner completing labs 01–03 in sequence ends with a working
  JWT-plus-session system, an RBAC-protected admin panel, and an
  ABAC-protected resource, each with a passing self-check.

#### Integration

- Tampered JWT signature is rejected; expired JWT is rejected; both produce
  an audit log entry with the specific denial reason.
- A user without the admin role is denied the admin panel and the denial is
  visible in the audit log.
- A non-owner request for another user's resource is denied by the policy
  evaluator, and the trace viewer shows the specific rule that fired.

#### Unit

- JWT verify function rejects a bad signature, an expired `exp`, and a
  missing required claim, each with a distinct error.
- RBAC middleware denies correctly for a role not in the allow-list.
- Policy evaluator returns the correct allow/deny plus matched-rule ID for a
  representative set of ABAC inputs.

## V3: Arc 2 — Labs 04–06 (OIDC Lab IdP, consent/revocation, service-to-service)

**Delivers:** R3, R1, R6, R8

**Build plan**

1. Lab 04: build the Lab IdP (ADR-0004) — authorization code flow with PKCE
   — and a client app that logs in against it; live redirect/token-exchange
   trace UI.
2. Lab 05: add incremental scope consent, a consent screen, token
   introspection, and revocation; demonstrate revocation killing a live
   session in the dashboard.
3. Lab 06: add client-credentials flow and mTLS (or API-key) service-to-
   service auth with no human present; demonstrate a call denied on a bad
   cert/key in the trace.
4. Introduce docker-compose here (ADR shape S8) since labs 04–06 now run
   multiple services (Lab IdP, resource server, client app) concurrently;
   confirm each service still runs standalone via `uvicorn`/`npm run dev`.
5. Run the generator, write handouts/self-checks/extension questions for all
   three labs.

**Demo:** a full OIDC login through the Lab IdP with a visible trace; a
learner revokes a token from the dashboard and watches the next request from
that session get denied in real time; a service-to-service call with a bad
credential is denied and shown in the trace.

**Rests on assumptions:** none new.

### Test plan

#### End-to-end

- A learner completing labs 04–06 has a working OIDC login, a working
  consent/revocation flow, and a working service-to-service auth path, each
  runnable via docker-compose with a passing self-check.

#### Integration

- Authorization code flow completes and issues a valid ID token; a PKCE
  mismatch is rejected.
- Revoking a token via the dashboard causes the next authenticated request
  using it to be denied within one request cycle.
- A service call with an invalid client credential/cert is denied and
  logged with the specific reason.

#### Unit

- PKCE code-verifier/challenge check passes only for the correct verifier.
- Consent scope set is correctly narrowed/widened on re-consent.
- Introspection endpoint correctly reports active vs. revoked for a given
  token.

## V4: Arc 3 first half — Labs 07–09 (first agent, scoped tools, on-behalf-of)

**Delivers:** R4 (partial), R1, R6, R7 (optional path scaffolded), R8

**Build plan**

1. Lab 07: add the agent identity type (ADR-0005's interface) and the
   deterministic scripted agent runner; agent acts on a schedule using its
   own service-account token; build the agent activity dashboard.
2. Wire the optional OpenAI-compatible-API-backed adapter (e.g. OpenRouter)
   behind the same interface as a clearly-marked stretch path (R7); confirm
   it can swap in without changing the agent-identity/token machinery.
3. Lab 08: add capability-scoped tokens limiting which tools/actions an
   agent may invoke; introduce OPA (ADR-0007) for this scoping policy;
   demonstrate a denied out-of-scope action in the audit trail.
4. Lab 09: add token-exchange-style delegation so an agent can act
   "on behalf of" a human, preserving the human's identity through an
   agent → downstream-API hop; make the `acting_as` claim visible end-to-end
   in the trace.
5. Run the generator, write handouts/self-checks/extension questions for
   all three labs.

**Demo:** the scripted agent runs unattended and its actions appear in the
dashboard under its own identity; an attempt to call an out-of-scope tool is
denied and shown in the audit trail; an on-behalf-of call shows the full
identity chain (human → agent → downstream API) in the trace.

**Rests on assumptions:** none new, but this is where the OPA-integration
open risk (PLAN.md) is first tested for real.

### Test plan

#### End-to-end

- A learner completing labs 07–09 has a running scripted agent with its own
  identity, a working scoped-tool denial, and a working on-behalf-of
  delegation, each with a passing self-check.
- The optional OpenAI-compatible-adapter path, if exercised, produces the same
  audit-log shape as the scripted agent for an equivalent action.

#### Integration

- An agent action outside its token's granted scope is denied by OPA and
  logged with the specific policy that denied it.
- An on-behalf-of call carries the original human's `sub` through to the
  downstream API's audit log, distinct from the agent's own identity.

#### Unit

- Capability-scoped token correctly encodes and later constrains the
  allowed action set.
- Token-exchange function correctly composes an `acting_as` claim without
  losing the original subject.

## V5: Arc 3 second half — Labs 10–11 (human-in-the-loop, multi-agent confused deputy)

**Delivers:** R4 (partial), R1, R6, R8

**Build plan**

1. Lab 10: add an approval-gate service; an agent's elevated-action request
   pauses until a human approves/denies via the pending-approval queue UI;
   approval issues a short-lived scoped token.
2. Lab 11: add a second agent identity and agent-to-agent calls; seed a real
   confused-deputy vulnerability (agent A's broad token is reused by agent B
   for an action it shouldn't be able to take), demonstrate the exploit,
   then fix it with proper per-hop scoping.
3. Run the generator, write handouts/self-checks/extension questions for
   both labs.

**Demo:** an agent's elevated action sits in the pending-approval queue
until a human clicks approve, then a short-lived token appears and the
action completes; the confused-deputy exploit is demonstrated succeeding,
then, after the fix, the same call sequence is denied.

**Rests on assumptions:** none new; lab 11's exploit realism is the open
risk flagged in PLAN.md, tested directly by this slice's demo.

### Test plan

#### End-to-end

- A learner completing labs 10–11 has a working approval-gate flow and can
  reproduce both the confused-deputy exploit and its fix, each with a
  passing self-check.

#### Integration

- An agent action requiring approval is blocked until a human decision is
  recorded, then proceeds only on approval, using a token that expires
  shortly after.
- Before the lab 11 fix: agent B successfully performs an action using
  agent A's forwarded token. After the fix: the same sequence is denied and
  logged as a scope violation.

#### Unit

- Approval-gate state machine transitions correctly (pending → approved /
  denied → expired).
- Per-hop scope-narrowing function strips any scope not explicitly
  re-granted at each agent-to-agent hop.

## V6: Capstone tail — Labs 12–13 (unified audit/revocation, open-ended capstone) + docs polish

**Delivers:** R4 (complete), R1, R5 (complete), R6, R8

**Build plan**

1. Lab 12: unify the audit/trace view across every identity type (human,
   service, agent) correlated by trace ID; add a revocation kill-switch that
   cuts off an in-flight agent's credentials immediately, visible live.
2. Lab 13 (capstone): assemble the open-ended extension brief — multiple
   human roles, multiple service accounts, multiple agents with scoped
   delegated tokens, the policy engine, approval gates, and the full audit
   trail all present at once; write the extension challenges.
3. Final docs pass: confirm all 14 handouts are present under
   `docs/course/`, navigation/search works on the deployed Zensical site,
   and every lab's starter/solution pair builds cleanly from a fresh clone.

**Demo:** revoking an agent's credentials from the dashboard mid-task
visibly halts its next action within one request cycle, correlated in the
unified trace; the deployed docs site navigates cleanly from lab 00 through
lab 13.

**Rests on assumptions:** none new.

### Test plan

#### End-to-end

- A learner completing lab 12 can revoke a live agent's credentials and
  observe its next action denied, with the whole human→agent→agent chain
  visible in one unified trace view.
- A fresh clone of the repo can build and run every lab's solution from
  00 through 13 without manual patching.
- The deployed GitHub Pages site serves all 14 handouts with working
  navigation and search.

#### Integration

- Revoking a credential mid-task is reflected in the next authorization
  check within one request cycle, regardless of which identity type
  (human/service/agent) it belongs to.
- A trace ID initiated by a human request and continued through two agent
  hops appears as one correlated timeline in the dashboard.

#### Unit

- Revocation check correctly consults the latest revocation state rather
  than a cached token validity result.
