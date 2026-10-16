import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stepper_gen as g  # noqa: E402

FLOW = """actors: A | B | C

step: First
msg: A -> B: hello
text: One.

step: Second
msg: C -> A: reply
note: B: remembers
text: Two,
  still two.

  And a second paragraph.
"""


def render(flow=FLOW):
    actors, steps = g.parse(flow)
    return g.render(actors, steps)


def test_parse_collects_steps_msgs_notes_and_multiline_text():
    actors, steps = g.parse(FLOW)
    assert actors == ["A", "B", "C"]
    assert [s["title"] for s in steps] == ["First", "Second"]
    assert steps[0]["msg"] == ("A", "B", "hello")
    assert steps[1]["notes"] == [("B", "remembers")]
    assert steps[1]["text"] == "Two,\nstill two.\n\nAnd a second paragraph."


def test_render_ids_and_highlight_targets_line_up():
    out = render()
    assert 'id="m1"' in out and 'id="m2"' in out and 'id="s2_1"' in out
    assert 'data-hl="m1"' in out
    assert 'data-hl="m2 s2_1"' in out


def test_arrow_direction_follows_message_direction():
    out = render()
    # A (x=100) -> B (x=350): tip at 350. C (600) -> A: tip at 100.
    assert 'points="350,100 341,95 341,105"' in out
    assert 'points="100,158 109,153 109,163"' in out


def test_figure_has_no_blank_lines():
    # A blank line would end the raw HTML block and md_in_html would mangle the SVG.
    fig = render().split("<figure")[1].split("</figure>")[0]
    assert "\n\n" not in fig


def test_text_is_markdown_but_titles_and_labels_are_escaped():
    out = render('actors: A | B\n\nstep: Say "hi" <now>\nmsg: A -> B: a & b\ntext: ok\n')
    assert "&amp;" in out and "&lt;now&gt;" in out and "&quot;hi&quot;" in out


@pytest.mark.parametrize(
    "flow, needle",
    [
        ("step: x\nmsg: A -> B: hi\ntext: t\n", "missing 'actors:'"),
        ("actors: A | B\n", "no steps"),
        ("actors: A\n\nstep: x\ntext: t\n", "at least two actors"),
        ("actors: A | B\n\nstep: x\nmsg: A -> Z: hi\ntext: t\n", "unknown actor 'Z'"),
        ("actors: A | B\n\nstep: x\nmsg: A -> A: hi\ntext: t\n", "two different actors"),
        ("actors: A | B\n\nstep: x\nmsg: A -> B: " + "w" * 90 + "\ntext: t\n", "too long"),
        ("actors: A | B\n\nstep: x\nmsg: A -> B: hi\n", "needs a title and text"),
        ("actors: A | B\n\nbogus line\n", "unrecognised line"),
        ("actors: A | B\n\nmsg: A -> B: hi\n", "before any 'step:'"),
    ],
)
def test_authoring_mistakes_fail_loudly(flow, needle):
    with pytest.raises(g.FlowError, match=needle):
        render(flow)


def test_inject_is_idempotent_and_check_detects_stale(tmp_path):
    (tmp_path / "f.flow").write_text(FLOW)
    page = tmp_path / "page.md"
    page.write_text("# T\n\n<!-- stepper: f.flow -->\n<!-- /stepper -->\n\nafter\n")
    assert g.main(["--inject", str(page)]) == 0
    once = page.read_text()
    assert 'class="stepper"' in once and once.rstrip().endswith("after")
    assert g.main(["--inject", str(page)]) == 0 and page.read_text() == once
    assert g.main(["--check", str(page)]) == 0
    (tmp_path / "f.flow").write_text(FLOW.replace("One.", "Uno."))
    assert g.main(["--check", str(page)]) == 1


def test_committed_pkce_flow_renders_with_seven_messages():
    flow = Path(__file__).resolve().parents[2] / "docs/course/flows/pkce.flow"
    out = g.from_file(flow)
    assert all(f'id="m{i}"' in out for i in range(1, 8))
