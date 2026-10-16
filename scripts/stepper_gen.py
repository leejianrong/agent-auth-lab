#!/usr/bin/env python3
"""Generate a handout stepper (ADR-0011) from a short text description.

A `.flow` file describes who talks to whom, one step at a time:

    actors: Browser | Client app | Lab IdP

    step: The user asks to log in
    msg: Browser -> Client app: click "Log in"
    text: The user clicks Log in. The app knows nothing about them yet.

    step: The app invents a secret and shares only its fingerprint
    msg: Client app -> Browser: redirect + code_challenge
    note: Client app: keeps code_verifier secret
    text: Anyone who intercepts the redirect learns the hash, not the secret.

Per step: `step:` (the heading) and `text:` (Markdown, may span following
lines until the next key) are required. `msg:` (`From -> To: label`) and any
number of `note:` (`Actor: text`) lines are optional. Blank lines separate
steps for readability only.

Usage:
    python3 scripts/stepper_gen.py docs/course/flows/pkce.flow
        prints the markup

    python3 scripts/stepper_gen.py --inject docs/course/lab-04-oidc.md
        replaces every block in the page between
        `<!-- stepper: flows/pkce.flow -->` and `<!-- /stepper -->` with the
        generated markup (path is relative to the page's own directory)

    python3 scripts/stepper_gen.py --check docs/course/lab-04-oidc.md
        exits non-zero if --inject would change the file (used in CI)

The markup relies on docs/course/javascripts/stepper.js and
docs/course/stylesheets/extra.css. The figure has no `markdown` attribute
and contains no blank lines, or md_in_html mangles the SVG.
"""
from __future__ import annotations

import argparse
import re
import sys
from html import escape
from pathlib import Path

WIDTH = 700
MARGIN_X = 100
TOP = 100
ROW = 58
CHAR_W = 6.6  # rough px per char at 12px, used for fit checks only


class FlowError(Exception):
    pass


def parse(text: str, source: str = "<flow>") -> tuple[list[str], list[dict]]:
    actors: list[str] = []
    steps: list[dict] = []
    cur: dict | None = None
    key: str | None = None

    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            if key == "text" and cur is not None:
                cur["text"].append("")  # paragraph break inside a text: block
            continue
        m = re.match(r"^(actors|step|msg|note|text):\s?(.*)$", line)
        if not m:
            if key == "text" and cur is not None:
                cur["text"].append(line.strip())  # continuation lines are left-trimmed
                continue
            raise FlowError(f"{source}:{n}: unrecognised line: {line!r}")
        k, v = m.group(1), m.group(2).strip()
        key = k
        if k == "actors":
            actors = [a.strip() for a in v.split("|") if a.strip()]
            if len(actors) < 2:
                raise FlowError(f"{source}:{n}: need at least two actors")
        elif k == "step":
            cur = {"title": v, "msg": None, "notes": [], "text": [], "line": n}
            steps.append(cur)
        else:
            if cur is None:
                raise FlowError(f"{source}:{n}: '{k}:' before any 'step:'")
            if k == "msg":
                mm = re.match(r"^(.+?)\s*->\s*(.+?)\s*:\s*(.+)$", v)
                if not mm:
                    raise FlowError(f"{source}:{n}: expected 'From -> To: label'")
                cur["msg"] = (mm.group(1), mm.group(2), mm.group(3))
            elif k == "note":
                nm = re.match(r"^(.+?)\s*:\s*(.+)$", v)
                if not nm:
                    raise FlowError(f"{source}:{n}: expected 'Actor: text'")
                cur["notes"].append((nm.group(1), nm.group(2)))
            else:
                cur["text"].append(v)

    if not actors:
        raise FlowError(f"{source}: missing 'actors:' line")
    if not steps:
        raise FlowError(f"{source}: no steps")
    for s in steps:
        s["text"] = "\n".join(s["text"]).strip()
        if not s["title"] or not s["text"]:
            raise FlowError(f"{source}:{s['line']}: every step needs a title and text")
    return actors, steps


def render(actors: list[str], steps: list[dict], source: str = "<flow>") -> str:
    n = len(actors)
    xs = [round(MARGIN_X + i * (WIDTH - 2 * MARGIN_X) / (n - 1)) for i in range(n)]
    pos = {a: i for i, a in enumerate(actors)}
    height = TOP + ROW * len(steps) + 30

    def idx(name: str, where: str) -> int:
        if name not in pos:
            raise FlowError(f"{source}: {where}: unknown actor {name!r} (actors: {', '.join(actors)})")
        return pos[name]

    svg: list[str] = []
    for a, x in zip(actors, xs):
        svg.append(
            f'<g class="actor"><rect x="{x - 55}" y="8" width="110" height="34" rx="6"/>'
            f'<text x="{x}" y="30" text-anchor="middle">{escape(a)}</text></g>'
        )
    for x in xs:
        svg.append(f'<line class="life" x1="{x}" y1="42" x2="{x}" y2="{height - 10}"/>')

    out_steps: list[str] = []
    for i, s in enumerate(steps, 1):
        y = TOP + ROW * (i - 1)
        hl: list[str] = []
        if s["msg"]:
            frm, to, label = s["msg"]
            a, b = idx(frm, f"step {i}"), idx(to, f"step {i}")
            if a == b:
                raise FlowError(f"{source}: step {i}: a message needs two different actors")
            x1, x2 = xs[a], xs[b]
            span = abs(x2 - x1)
            text = f"{i} {label}"
            if len(text) * CHAR_W > span - 16:
                raise FlowError(
                    f"{source}: step {i}: label {text!r} is too long for the gap between "
                    f"{frm} and {to} ({len(text)} chars, about {int((span - 16) / CHAR_W)} fit)"
                )
            d = 1 if x2 > x1 else -1
            tip, base = x2, x2 - d * 9
            svg.append(
                f'<g class="msg" id="m{i}"><line x1="{x1}" y1="{y}" x2="{base}" y2="{y}"/>'
                f'<polygon points="{tip},{y} {base},{y - 5} {base},{y + 5}"/>'
                f'<text x="{(x1 + x2) // 2}" y="{y - 7}" text-anchor="middle">{escape(text)}</text></g>'
            )
            hl.append(f"m{i}")
        for k, (actor, ntext) in enumerate(s["notes"], 1):
            a = idx(actor, f"step {i} note")
            w = int(len(ntext) * 6.0 + 18)
            x = xs[a] + 10 if a < n - 1 else xs[a] - w - 10
            nid = f"s{i}_{k}"
            svg.append(
                f'<g class="secret" id="{nid}"><rect x="{x}" y="{y + 6}" width="{w}" height="22"/>'
                f'<text x="{x + w // 2}" y="{y + 21}" text-anchor="middle">{escape(ntext)}</text></g>'
            )
            hl.append(nid)
        out_steps.append(
            f'<div class="step" data-title="{escape(s["title"], quote=True)}" '
            f'data-hl="{" ".join(hl)}" markdown>\n{s["text"]}\n</div>'
        )

    label = "Sequence diagram: " + ", ".join(actors)
    figure = (
        '<figure class="stepper-diagram">\n'
        f'<svg class="flow" viewBox="0 0 {WIDTH} {height}" role="img" aria-label="{escape(label, quote=True)}">\n'
        + "\n".join(svg)
        + "\n</svg>\n</figure>"
    )
    return '<div class="stepper" markdown>\n\n' + figure + "\n\n" + "\n\n".join(out_steps) + "\n\n</div>"


def from_file(path: Path) -> str:
    actors, steps = parse(path.read_text(), str(path))
    return render(actors, steps, str(path))


BLOCK = re.compile(
    r"(<!-- stepper: (?P<src>\S+) -->\n)(?P<body>.*?)(<!-- /stepper -->)", re.DOTALL
)


def inject(page: Path) -> str:
    text = page.read_text()

    def sub(m: re.Match) -> str:
        flow = (page.parent / m.group("src")).resolve()
        if not flow.is_file():
            raise FlowError(f"{page}: flow file not found: {m.group('src')}")
        return m.group(1) + from_file(flow) + "\n" + m.group(4)

    new, count = BLOCK.subn(sub, text)
    if count == 0:
        raise FlowError(f"{page}: no '<!-- stepper: ... -->' blocks found")
    return new


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", type=Path)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--inject", action="store_true", help="rewrite stepper blocks in a markdown page")
    mode.add_argument("--check", action="store_true", help="fail if --inject would change the page")
    args = ap.parse_args(argv)
    try:
        if args.inject:
            new = inject(args.path)
            if new != args.path.read_text():
                args.path.write_text(new)
                print(f"updated {args.path}")
            else:
                print(f"{args.path} already up to date")
        elif args.check:
            if inject(args.path) != args.path.read_text():
                print(f"{args.path}: stepper blocks are stale, run with --inject", file=sys.stderr)
                return 1
            print(f"{args.path}: ok")
        else:
            print(from_file(args.path))
    except FlowError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
