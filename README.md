# Agent Auth Lab

A 14-lab, hands-on course on authentication and authorization: starting from
sessions and JWTs, through OAuth2/OIDC, to authn/authz for autonomous agents.
Published as a [Zensical](https://zensical.org/) docs site; see `docs/course/`
for the handouts and `labs/` for the code.

Read `PLAN.md` first, then `docs/adr/` for the reasoning behind each
architectural decision, `SLICES.md` for the build plan, and `CLAUDE.md` for
repo conventions.

## Quick start

```sh
make lab00-setup   # install lab 00's backend + frontend dependencies
make lab00-test    # run lab 00's solution self-check suite
make lab00-run     # run lab 00's starter backend + frontend
make docs-serve    # preview the course site locally
```

## Repo layout

- `labs/lab-NN-slug/{starter,solution}/` — one folder per lab.
- `shared/observability-harness/` — the audit-log + trace-ID + dashboard
  package every lab imports.
- `docs/course/` — the published lab handouts (Zensical source).
- `docs/adr/` — architectural decision records.
- `scripts/generate_starter.py` — generates a lab's `starter/` from its
  `solution/`; see the script's docstring for the sentinel-comment
  convention it relies on.
