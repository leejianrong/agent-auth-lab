# ADR-0006: Custom lightweight observability harness instead of OpenTelemetry + Jaeger/Zipkin

- Status: Accepted
- Date: 2026-08-19
- Deciders: user, agent (F3)

## Context

Requirement R1 is that every lab produce an observable outcome, and several
labs (12 especially) need a *unified* trace across human, service, and agent
identities. The realistic production answer is OpenTelemetry exporting to
Jaeger or Zipkin. But that requires learners to run and understand an
additional service (typically via docker-compose) before they've built
anything of their own — infrastructure friction against a self-paced junior
audience, for a course whose subject is auth, not observability tooling.

## Decision

Build one shared package, `/shared/observability-harness`: structured JSON
audit-log events, an OTel-shaped trace-ID convention (so the concept
transfers to real OTel later), and a small pre-built Svelte dashboard that
renders the log/trace stream. Every lab imports and runs this harness; no
lab asks the learner to build or operate Jaeger/Zipkin/an OTel collector.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Real OpenTelemetry + Jaeger via docker-compose | More production-realistic, but adds a service to run and a UI to learn (Jaeger's own console) before lab 01 is even done; the course's subject is auth, and this would compete for attention |
| Plain `print()`/log-file output, no dashboard at all | Fails R1 for several labs (07, 10, 12) where the whole point is watching an approval queue or a live revocation happen in a UI, not grepping a log file |

## Consequences

- Learners get a dashboard from lab 00 onward without building or
  understanding tracing infrastructure first — the harness is explicitly a
  provided tool, not a taught concept (matches the user's "some tools they
  don't have to code, just use").
- Trace IDs are deliberately shaped like OTel's so the concept transfers if a
  learner later adopts real OpenTelemetry professionally — a one-line
  mention in the lab 12 handout makes this explicit.
- Forecloses the course from demonstrating a real production observability
  stack; if that's ever wanted, it would be a new optional stretch lab, not a
  retrofit of the harness used everywhere else.
