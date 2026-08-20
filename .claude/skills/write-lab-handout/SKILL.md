---
name: write-lab-handout
description: Write or edit a lab handout for the Agent Auth Lab course (docs/course/lab-NN-*.md). Use whenever drafting a new lab's handout or revising an existing one. Covers handout structure, the previous-lab walkthrough, diagram requirements, and what may and may not be shown as code.
---

# Writing an Agent Auth Lab handout

This skill operationalizes ADR-0010. Read that ADR for the reasoning; this
is the checklist for actually writing the thing.

## Always start with `/natural-writing`

Before drafting or editing a single sentence, invoke the `/natural-writing`
skill. This applies to every handout, not just the prose-heavy sections:
vary sentence rhythm, cut hedging and stock vocabulary, no em-dashes, no
title-case headings. Learner-facing material gets read by a junior
developer trying to learn, not skimmed by someone who already knows the
domain, so stiff or visibly AI-flavored prose costs the most here.

## Handout structure, in order

1. **Title and objectives.** What this lab builds and what you'll learn.
2. **Closing the loop on the previous lab** (every lab except 00):
   - A walkthrough of the previous lab's task solutions: what the fix was
     and why, with a diagram if the fix itself is non-obvious (not just a
     one-line "and now it's fixed"). This is not the same content as that
     lab's own handout: here you're allowed to show and explain the actual
     solution code, because it's no longer the lab being introduced.
   - A discussion of that lab's "going further" questions: your own
     considered take on each one. This is one perspective, not a graded
     answer key, and it should read like a colleague thinking out loud, not
     a marking scheme.
3. **Background / concepts** for *this* lab, with at least one diagram (see
   below). This is where new material gets introduced.
4. **Prerequisites and setup.**
5. **Your tasks**, one per TODO in this lab's starter. See "No spoilers"
   below for what may and may not be shown here.
6. **You're done when**, a concrete checklist tied to the self-check suite
   plus any manual/visual checks.
7. **Going further** for *this* lab: open-ended questions with no
   self-check. Next lab's handout will discuss these, so don't answer them
   here.
8. **Further reading.**

## No spoilers, but only for the lab being introduced

When describing this lab's own tasks:

- Show the **starter's** code, TODO comment and all, never the fix.
- Point at the specific file and function to open.
- Describe what property the fix must have (which library, which behavior
  changes) in prose. Naming a specific method to use (e.g. "`.hash()` on
  `PasswordHasher`") is fine; writing out the finished line that calls it is
  not.
- If a warning or gotcha applies (e.g. "don't simplify this signature, a
  later lab reuses it"), say so, but still don't show the fixed code.

This restriction lifts entirely once you're discussing the *previous* lab
in section 2 above. There, show the actual solution code if it helps the
explanation, and diagram it if the mechanism isn't obvious from the code
alone.

Before publishing, verify every code excerpt actually matches the real
file it claims to quote:

```sh
grep -c "<snippet text>" labs/lab-NN-slug/starter/backend/app/whatever.py
```

A snippet that drifted from the real starter/solution during editing is
worse than no snippet.

## Diagrams

At least one diagram per background/explainer section. A wall of prose
explaining a mechanism (a request flow, an attack, a delegation chain) is
exactly what a diagram should replace.

- **Default to Mermaid.** Zensical renders it natively from a fenced
  ` ```mermaid ` block, no extra asset pipeline. Sequence diagrams for
  request/response flows and attacks, flowcharts for decision logic,
  swimlane-style subgraphs for multi-actor processes.
- **C4-style architecture diagrams** are for labs with an actual
  multi-service system to show (lab 04 onward, once there's a Lab IdP, a
  resource server, and clients as separate services). Don't reach for C4 in
  a single-service lab; a sequence or flow diagram of the mechanism fits
  better.
- **Screenshots of the running app** are used where they'd clarify an
  observable outcome (what a panel looks like, what a denied request shows
  in the UI). This repo has no browser-automation tooling to capture one,
  so either describe precisely what to look for in prose, or name the
  specific graphic wanted (what it should show, roughly what it should look
  like) so it can be generated or supplied separately. Never leave the spot
  as a bare placeholder.

## Verifying before you're done

1. Build the docs site and confirm it's still clean:
   `zensical build --clean --strict` (or `make docs-build`).
2. Confirm Mermaid blocks actually rendered rather than sitting as raw
   fenced code: `grep -o 'class="mermaid"' site/lab-NN-slug/index.html`.
3. Confirm no solution-only code leaked into a section about the current
   lab's own tasks: grep the built HTML for a distinguishing line from
   `solution/` and expect zero hits there.
