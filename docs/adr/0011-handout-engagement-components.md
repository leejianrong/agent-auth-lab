# ADR-0011: Engagement components for lab handouts, from lab 04 on

- Status: Accepted
- Date: 2026-10-16
- Deciders: user
- Amends: ADR-0010 (rules 2 and 3, for labs 04 onward)

## Context

Labs 00-03 are well structured but a learner can only read them. Between
them they have 2-4 Mermaid diagrams each, three screenshots in total, and no
interactive element, at 1,500-2,900 words a lab. The AAL-11 spike
(`docs/research/handout-engagement.md`) prototyped three components in
Zensical, checked them in Chromium in light and dark mode, and measured what
they cost. The evidence is thin in one respect: no real learner has used
them yet.

## Decision

From lab 04 onward, handouts use these components. Labs 00-03 are left as
they are for now and get a retrofit later, after a real-learner test.

1. **Stepper clickthrough** for every multi-party flow (OIDC, token
   exchange, on-behalf-of, approval). It animates a diagram one message at a
   time, with a sentence per step saying what to notice. It must degrade to
   plain prose with JavaScript off. A stepper counts as the required diagram
   for that section, which amends ADR-0010 rule 2. Static Mermaid or C4
   stays the right choice for architecture, where shape matters and sequence
   does not.
2. **Stepper diagrams are generated, not hand-drawn.** A small script turns
   a short text description of the sequence into the figure markup. The
   generator (AAL-12) lands before lab 04's handout needs it.
3. **Predict-then-reveal fold before each observable outcome.** Each lab
   already names one outcome (a denial, a trace line, a failed signature).
   Before the learner triggers it, a fold asks what they expect to happen.
   The answer must not spoil the lab being introduced (ADR-0010 rule 1).
4. **Break-it widgets, one per arc.** A self-contained HTML file embedded in
   the handout, where the learner tampers with something and sees the
   verdict. The JWT tamper widget covers arc 1. Arc 2 gets one on scopes or
   policy, arc 3 one on delegation chains. A widget sits beside the sentence
   it illustrates and comes with a task.
5. **Handout layout.** The first task is visible within the first two
   screens. The previous-lab walkthrough and the long background block are
   collapsed folds, so the walkthrough still opens the handout as ADR-0010
   rule 3 requires, but a learner who finished last time can skip it. This
   amends rule 3's ordering, not its content.
6. **Real-learner test.** One person works lab 02 start to finish while we
   watch, before any retrofit of labs 00-03 or any widening of the
   component set (AAL-15).

Prototype code lives in `docs/course/javascripts/` (`stepper.js`,
`embed.js`), `docs/course/stylesheets/extra.css` and
`docs/course/widgets/`. The `write-lab-handout` skill carries the authoring
rules.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Retrofit labs 00-03 at the same time | Touches four finished handouts before we know what works, and each carries tutorial maintenance cost. Deferred, not rejected |
| Hand-write each stepper SVG | Seven messages is already tedious, and lab 11 needs more. Edits mean recomputing coordinates |
| Mermaid plus a numbered list instead of a stepper | No animation, which is the main benefit |
| A widget per lab | More than ten pieces to keep working as labs change, and several labs have nothing to break |
| Video | High production cost and hard to keep in step with the code |
| A quiz plugin | We have no way to grade and no need to |
| Keep the ADR-0010 order | The long wait before the first action stays |

## Consequences

- Each new handout carries extra authoring work: a stepper source file, one
  or more checkpoint questions, and sometimes a widget. The generator is
  what keeps the stepper part cheap.
- Interactive pieces can break when a lab changes. Handout review now
  includes running the page and clicking through each component.
- Widgets are iframes, so they don't inherit site CSS. The theme relay in
  `embed.js` handles dark mode, but fonts and spacing are duplicated until a
  shared stylesheet exists.
- Widgets use throwaway secrets in the browser. They say so on the page and
  never accept a real credential.
- Labs 00-03 will look different from lab 04 onward until the retrofit.
- ADR-0010 rule 2 now reads "at least one diagram per background section,
  and a stepper satisfies it". Rule 3 now reads "opens with the previous
  lab's walkthrough, collapsed by default".
