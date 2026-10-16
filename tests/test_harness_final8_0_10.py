"""Final security pass 8, harness findings #4 and #5.

#4: masking an unterminated private-key marker re-read the rest of the string for
every marker (an ``END`` search and a whole-tail ``splitlines`` per marker), so one
event line full of ``BEGIN`` markers cost O(markers x length) of synchronous CPU,
past the harness timeout. #5: an unpaired UTF-16 surrogate escape in any event
(``"caf\\ud83d"`` from a Node CLI) was recorded as a lone surrogate, which the
``.tine`` writer refuses: the whole run was lost, and with autosave the agent was
killed mid-run.
"""

from __future__ import annotations

import json
import sys
import time

import pytest

from opentine.core import Run
from opentine.harnesses import (
    HARNESS_CLASSES,
    ClaudeCodeHarness,
    CodexCLIHarness,
    GenericHarness,
    OpentineHarness,
)
from opentine.harnesses._key_extent import masked_text, open_after
from opentine.harnesses._key_mask import KeyLines
from opentine.harnesses._key_patterns import PLACEHOLDER
from opentine.harnesses._record_depth import _recordable, escaped_text

MARKER = "-----BEGIN RSA PRIVATE KEY-----"


def _best(call, value, rounds: int = 3) -> float:
    best = float("inf")
    for _ in range(rounds):
        started = time.perf_counter()
        call(value)
        best = min(best, time.perf_counter() - started)
    return best


def _grows_linearly(call, unit: str, small: int) -> None:
    short, long = _best(call, unit * small), _best(call, unit * small * 4)
    assert long < max(short, 0.01) * 6, (short, long)


@pytest.mark.parametrize(
    "unit",
    [
        MARKER + " ",  # one line of markers: each marker's line is prose at once
        MARKER + "\nMIIEpAIBAAKCAQEA\n",  # marker, body line, marker, ...
        MARKER + "Proc-Type: 4,ENCRYPTED ",  # a header line is read once, not per marker
        MARKER + "\n\n",
    ],
)
def test_masking_is_linear_in_the_number_of_markers(unit):
    _grows_linearly(masked_text, unit, 4000)
    _grows_linearly(open_after, unit, 4000)


def test_a_megabyte_of_markers_in_one_event_line_masks_quickly():
    text = (MARKER + " ") * 30000  # ~1 MB, 30k unterminated markers
    line = json.dumps(
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": text}]}}
    )
    started = time.perf_counter()
    masked = KeyLines().mask(line)
    assert time.perf_counter() - started < 10
    assert MARKER not in masked
    _grows_linearly(lambda value: KeyLines().mask(value), json.dumps({"text": MARKER + " "}), 1)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"{MARKER}\nMIIE\nsome prose", f"{PLACEHOLDER}some prose"),
        (f"a {MARKER} b {MARKER}\nMIIE\nc d", f"a {PLACEHOLDER} b {PLACEHOLDER}c d"),
        (f"{MARKER}Proc-Type: 4 {MARKER} x\nMIIE", PLACEHOLDER),
        (f"{MARKER}\nMIIE\n-----END RSA PRIVATE KEY----- tail", f"{PLACEHOLDER} tail"),
    ],
)
def test_masking_keeps_its_extent_rules(text, expected):
    assert masked_text(text) == expected


def test_recordable_escapes_lone_surrogates_and_says_so():
    value = {"text": "caf\ud83d", "k\udc9d": ["ok", {"n": "\ud800x"}], "fine": "😀"}
    recorded = _recordable(value)
    assert recorded["surrogates_escaped"] is True
    assert recorded["text"] == "caf\\ud83d"
    assert recorded["k\\udc9d"] == ["ok", {"n": "\\ud800x"}]
    assert recorded["fine"] == "😀"
    assert _recordable({"text": "plain 😀"}) == {"text": "plain 😀"}
    assert escaped_text(None) is None


def _printer(tmp_path, lines: list[str], *flags: str) -> tuple[str, ...]:
    """A stand-in CLI printing *lines*; trailing flags (ignored by ``-c``) mirror the
    real CLI's JSON mode so the harness trusts its events."""
    (tmp_path / "out.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    script = "import sys\nsys.stdout.write(open('out.txt').read()); sys.stdout.flush()\n"
    return (sys.executable, "-c", script, *flags)


#: Event shapes from several dialects, each carrying a lone surrogate escape.
_SURROGATE_LINES = [
    '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1",'
    '"content":"caf\\ud83d"}]}}',
    '{"type":"message","role":"assistant","content":"Caf\\udc9d menu","delta":true}',
    '{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"x\\ud83d"}}',
    '{"type":"text","text":"y\\ud800","model":"m\\ud83d"}',
    '{"type":"tool_use","name":"n\\udc00","input":{"k\\ud83d":"v\\ud83d"}}',
    '{"type":"result","result":"done \\ud83d","total_cost_usd":0.5}',
    "plain text after",
]


def _classes():
    found = {"claude-code": ClaudeCodeHarness, "codex": CodexCLIHarness}
    found["generic"] = GenericHarness
    found.update(HARNESS_CLASSES)
    return sorted(found.items())


@pytest.mark.parametrize(("name", "cls"), _classes())
def test_a_lone_surrogate_in_any_dialect_still_saves(tmp_path, name, cls):
    flags = tuple(getattr(cls, "default_command", ())[1:]) or ("--output-format", "json")
    if name == "codex":
        flags = ("exec", "--json")
    harness = cls(command=_printer(tmp_path, _SURROGATE_LINES, *flags), cwd=tmp_path)
    wrapped = OpentineHarness(harness, autosave_path=tmp_path / "auto.tine", autosave_steps=1)
    run = wrapped.run_sync("task", save_path=tmp_path / "out.tine")
    assert run.status.value == "completed", name
    saved = Run.load(tmp_path / "out.tine")
    assert saved.status.value == "completed"
    assert len(saved.steps) == len(run.steps)
    assert Run.load(tmp_path / "auto.tine").status.value == "completed"


def test_claude_code_records_escaped_text_and_runs_to_the_end(tmp_path):
    lines = [
        _SURROGATE_LINES[0],
        '{"type":"assistant","message":{"id":"m2","model":"claude-opus-5-5","content":'
        '[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"rm -rf build"}}],'
        '"usage":{"input_tokens":5,"output_tokens":2}}}',
        _SURROGATE_LINES[5],
    ]
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines, "--output-format", "stream-json"), cwd=tmp_path
    )
    run = OpentineHarness(harness, autosave_path=tmp_path / "a.tine", autosave_steps=1).run_sync(
        "task", save_path=tmp_path / "out.tine"
    )
    text = (tmp_path / "out.tine").read_text(encoding="utf-8")
    assert "rm -rf build" in text  # the steps after the surrogate were recorded
    assert "caf\\\\ud83d" in text and "surrogates_escaped" in text
    assert run.status.value == "completed"
