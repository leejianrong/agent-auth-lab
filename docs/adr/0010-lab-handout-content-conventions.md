# ADR-0010: No spoilers, diagrams over prose walls, cross-lab discussion of open questions

- Status: Accepted
- Date: 2026-08-20
- Deciders: user

## Context

The lab 00 handout, as first written, showed the corrected implementation
inline (the fixed `hash_password`, the fixed `resolve_login_session_id`),
and leaned entirely on prose for its background section despite Zensical
already rendering Mermaid diagrams natively via the `pymdownx.superfences`
config in `zensical.toml`. The "going further" open questions at the end
were well received, but had no mechanism for a learner to see any considered
answer to them, since they're deliberately open-ended and unscored.

## Decision

Three standing rules for every lab handout from here on:

1. **No solution code in the handout.** Code excerpts shown are always the
   starter's state: the naive/incomplete implementation with its
   `TODO(lab-NN)` comment, never the fix. Where the fix needs explaining, the
   handout names the file and function to open and describes, in prose, the
   property the fix must have (which library, which behavior to change),
   without pasting the corrected code. The reference implementation lives
   only in `solution/`, for after a real attempt.
2. **At least one diagram per background/explainer section**, not prose
   alone. Mermaid (sequence diagrams, flowcharts, swimlane-style subgraphs)
   is the default, since it's plain text in the markdown source and Zensical
   renders it with no extra asset pipeline. C4-style architecture diagrams
   are reserved for labs with an actual multi-service system to show (lab 04
   onward); a single-service lab gets a sequence or flow diagram of the
   mechanism instead. A screenshot of the running app is used where it would
   clarify an observable outcome; since this repo has no browser-automation
   tooling to capture one, the handout either describes precisely what to
   look for in prose, or names the specific graphic wanted so the course
   author can generate or supply it.
3. **Every handout (lab 00 excepted, being first) opens with a short
   discussion of the previous lab's "going further" questions** before its
   own material, then closes with its own new set. The discussion offers one
   considered perspective, not a graded answer key.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Publish an answer key alongside "going further" questions | Defeats the point of an open-ended question, which is meant to provoke thinking, not be checked against a hidden key |
| Prose-only handouts, no diagrams | Explicitly the feedback being addressed here, and leaves free Mermaid rendering unused |
| A separate "answers" page instead of discussing inline at the top of the next handout | Splits a continuous read across two pages for no real benefit |

## Consequences

- Every future lab's authoring workload now includes drafting real
  discussion of the *previous* lab's open questions. This is a standing
  per-lab cost, not a one-time template change, and it means lab N's handout
  can't be finalized independently of lab N-1's "going further" section.
- Diagram design becomes a per-lab authoring task. Mermaid keeps the
  mechanics cheap, but someone still has to design each diagram to show the
  actual mechanism rather than decorate the page.
- Reviewing a handout before publishing now includes checking that any shown
  code excerpt genuinely matches `starter/`, not something that quietly
  drifted from `solution/` during editing.
- Real screenshots remain a gap until this repo has a way to generate them
  (browser automation) or the course author supplies them directly; handouts
  should name what's needed rather than embed a placeholder.
