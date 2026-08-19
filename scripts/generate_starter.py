#!/usr/bin/env python3
"""Generate a lab's `starter/` tree from its `solution/` tree.

Convention (works in any comment syntax — Python `#`, JS `//`, HTML/Svelte
`<!-- -->` — since it's matched as a plain substring, not a language-specific
comment token):

    LAB:SOLUTION >>>
    <code that only belongs in the reference solution>
    LAB:SOLUTION <<<
    LAB:STARTER >>>
    <TODO comment / stub / intentionally-naive code for the learner to fix>
    LAB:STARTER <<<

Everything outside a LAB:SOLUTION/LAB:STARTER pair is copied to the starter
verbatim — it's the code every learner needs regardless of what they've
built yet. This keeps the starter as a scripted diff of the solution rather
than a hand-maintained parallel copy (ADR-0003), so the two can't silently
drift apart.

A whole file can be excluded from the starter (e.g. answer-key notes) by
making its first line contain `LAB:FILE-SOLUTION-ONLY`.

IMPORTANT for Python files: a LAB:SOLUTION block must end in `return`/`raise`
(or be the last statement in its suite). The solution file is committed and
run as-is — both blocks are physically present in the source — so if the
SOLUTION code doesn't return/raise, execution falls through into the
STARTER block right below it and both run, with the naive STARTER statement
silently winning. This generator refuses to emit a starter (raising
GeneratorError) for any `.py` LAB:SOLUTION block that doesn't end that way,
since that's exactly the bug it would otherwise hide.

Usage:
    python scripts/generate_starter.py <lab-dir>
    # reads <lab-dir>/solution, writes <lab-dir>/starter

    python scripts/generate_starter.py --check <lab-dir>
    # exits non-zero if regenerating would change the committed starter
    # (catches solution edits that were never propagated)
"""

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

SOLUTION_BEGIN = "LAB:SOLUTION >>>"
SOLUTION_END = "LAB:SOLUTION <<<"
STARTER_BEGIN = "LAB:STARTER >>>"
STARTER_END = "LAB:STARTER <<<"
FILE_SOLUTION_ONLY = "LAB:FILE-SOLUTION-ONLY"

SKIP_DIR_NAMES = {
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".svelte-kit",
}

# Extensions we know how to text-transform. Anything else is copied verbatim
# (or, if binary and unreadable as text, copied verbatim via the fallback).
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".svelte", ".html", ".css", ".json", ".md",
    ".toml", ".cfg", ".ini", ".yml", ".yaml", ".txt", ".sh",
}


class GeneratorError(Exception):
    pass


_TERMINATORS = ("return", "raise")


def _assert_terminates(block_lines: list[str], source: str) -> None:
    """A LAB:SOLUTION block in a .py file must end in return/raise, so the
    STARTER block physically below it in the same committed file can never
    execute when the solution itself is run — see the module docstring."""
    non_blank = [ln for ln in block_lines if ln.strip() and not ln.strip().startswith("#")]
    if not non_blank:
        raise GeneratorError(f"{source}: empty LAB:SOLUTION block")
    last = non_blank[-1].strip()
    if not last.startswith(_TERMINATORS):
        raise GeneratorError(
            f"{source}: LAB:SOLUTION block must end with return/raise, "
            f"got {last!r} — otherwise the STARTER block right after it "
            f"would also execute when this file is run as the solution"
        )


def transform_text(text: str, *, source: str) -> str | None:
    """Return the starter version of `text`, or None if the file is
    solution-only and should be excluded entirely."""
    lines = text.splitlines(keepends=True)
    if lines and FILE_SOLUTION_ONLY in lines[0]:
        return None

    out = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if SOLUTION_BEGIN in line:
            i += 1
            block_lines = []
            while i < n and SOLUTION_END not in lines[i]:
                block_lines.append(lines[i])
                i += 1
            if i == n:
                raise GeneratorError(f"{source}: {SOLUTION_BEGIN!r} without matching {SOLUTION_END!r}")
            if source.endswith(".py"):
                _assert_terminates(block_lines, source)
            i += 1  # skip the SOLUTION_END line itself
            continue
        if STARTER_BEGIN in line:
            i += 1
            while i < n and STARTER_END not in lines[i]:
                out.append(lines[i])
                i += 1
            if i == n:
                raise GeneratorError(f"{source}: {STARTER_BEGIN!r} without matching {STARTER_END!r}")
            i += 1  # skip the STARTER_END line itself
            continue
        out.append(line)
        i += 1
    return "".join(out)


def generate(solution_dir: Path, starter_dir: Path) -> None:
    if not solution_dir.is_dir():
        raise GeneratorError(f"no such solution directory: {solution_dir}")

    if starter_dir.exists():
        shutil.rmtree(starter_dir)
    starter_dir.mkdir(parents=True)

    for src in sorted(solution_dir.rglob("*")):
        rel = src.relative_to(solution_dir)
        if any(part in SKIP_DIR_NAMES for part in rel.parts):
            continue
        dst = starter_dir / rel

        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.suffix in TEXT_EXTENSIONS:
            text = src.read_text(encoding="utf-8")
            result = transform_text(text, source=str(rel))
            if result is None:
                continue  # solution-only file, excluded from starter
            dst.write_text(result, encoding="utf-8")
        else:
            shutil.copy2(src, dst)


def check(solution_dir: Path, starter_dir: Path) -> bool:
    """Regenerate into a temp dir and diff against the committed starter.
    Returns True if they match (starter is up to date)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_starter = Path(tmp) / "starter"
        generate(solution_dir, tmp_starter)

        cmp = filecmp.dircmp(tmp_starter, starter_dir)
        return _dirs_equal(cmp)


def _dirs_equal(cmp: filecmp.dircmp) -> bool:
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    return all(_dirs_equal(sub) for sub in cmp.subdirs.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("lab_dir", type=Path, help="lab directory containing solution/ and starter/")
    parser.add_argument("--check", action="store_true", help="verify starter is up to date instead of writing it")
    args = parser.parse_args()

    solution_dir = args.lab_dir / "solution"
    starter_dir = args.lab_dir / "starter"

    try:
        if args.check:
            if check(solution_dir, starter_dir):
                print(f"OK: {starter_dir} matches generated output")
                return 0
            print(f"STALE: {starter_dir} does not match what solution/ would generate; re-run without --check", file=sys.stderr)
            return 1
        generate(solution_dir, starter_dir)
        print(f"generated {starter_dir} from {solution_dir}")
        return 0
    except GeneratorError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
