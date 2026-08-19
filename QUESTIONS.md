# Questions

Statuses: `DECIDED` (user answered) · `ASSUMED` (default taken, correct it if
wrong) · `FORK` (waiting on the user) · `DEFERRED` (not needed this
milestone).

## Open forks

*(empty — round closed)*

## Register

| ID | Question | Status | Answer or default | Landed |
|----|----------|--------|--------------------|--------|
| Q1 | What language/framework for all lab backends? | DECIDED | Python + FastAPI | ADR-0001 |
| Q2 | What for the frontend, when a lab needs one? | DECIDED | Svelte + Vite | ADR-0001 |
| Q3 | Real LLM-powered agents or deterministic scripted agents by default? | DECIDED | Scripted by default; any OpenAI-compatible API (e.g. OpenRouter) as optional stretch path | ADR-0005 |
| Q4 | Observability approach: custom dashboard or real OpenTelemetry+Jaeger/Zipkin? | DECIDED | Custom lightweight harness, OTel-shaped trace IDs, no Jaeger requirement | ADR-0006 |
| Q5 | Policy engine: hand-rolled throughout, or a real engine (OPA) from the start? | DECIDED | Hybrid — hand-rolled labs 02–03, OPA introduced lab 08+ | ADR-0007 |
| F5 | Is a 14-lab (00–13) syllabus at this depth right, or should it be tighter/looser? | DECIDED | Confirmed as proposed | PLAN.md §Shape |
| Q6 | Who is this course for — solo learner, cohort, something else? | ASSUMED | Solo, self-paced junior developer, no cohort or grading | PLAN.md §Users and actors |
| Q7 | What datastore backs the capstone system? | ASSUMED | SQLite only, across every lab | ADR-0002 |
| Q8 | Real vendor IdP (Keycloak/Auth0) or self-built? | ASSUMED | Self-built teaching-grade Lab IdP | ADR-0004 |
| Q9 | How is intentionally-vulnerable pedagogical code kept safe? | ASSUMED | Labeled, localhost-only, always paired with the fix, secrets via `.env`/`.gitignore` | ADR-0008 |
| Q10 | Is there autograding or scoring? | ASSUMED | No — self-check pytest suites are advisory only, nothing submitted | PLAN.md §Scope |
| Q11 | Does every lab need Docker/docker-compose? | ASSUMED | Only from lab 06 onward, once multiple services run concurrently; earlier labs stay single-service | PLAN.md §Shape (S8) |
| Q12 | Does course content need a versioning/migration plan? | ASSUMED | No — single version for v1, revisit if a v2 happens | PLAN.md §Scope |
| Q13 | Are WebAuthn/passkeys, mobile auth, or IdP governance (SailPoint-style) in scope? | ASSUMED | Out of scope for v1; mentioned only as reading pointers | PLAN.md §Scope |
| Q14 | Where does the Zensical docs source live, given `docs/adr/` and repo-root planning files already occupy `docs/`? | ASSUMED | `docs/course/`, config at repo root | ADR-0009 |
| Q15 | How are per-lab starter scaffolds produced from each lab's solution? | ASSUMED | Scripted solution→starter diff, not hand-maintained in parallel | ADR-0003 |
| Q16 | What does "ZeroID" (mentioned by the user) refer to, and does it belong in the course? | DEFERRED | Not a term the agent has confident grounding on; no course content added until the user clarifies what they mean | n/a |

## Coverage

| Category | Covered by |
|----------|-----------|
| Primary user and actors | Q6 |
| Scope boundary | F5, Q13 |
| Data model and identity | PLAN.md §Implementation decisions (agent identity as first-class type) |
| State and storage | Q7 |
| Concurrency and conflict | PLAN.md §Scope (out — last-write-wins) |
| Interfaces and contracts | Q1, Q2, Q11 |
| Failure behaviour | Q9, ADR-0008 |
| External dependencies | Q4, Q5, Q8 |
| Runtime and deployment | Q11, Q14 |
| Measurable success | PLAN.md §Testing approach, SLICES.md end-to-end lines |
| Security and secrets | Q9 |
| Versioning and migration | Q12 |
