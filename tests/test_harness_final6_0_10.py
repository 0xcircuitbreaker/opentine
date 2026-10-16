"""Final security pass 6 (0.10.0) harness fixes, pinned.

* #7 the joined output kept a raw marker line while the output cap charged only
  its masked form, so ``-----BEGIN PRIVATE KEY----- <1 MB>`` cost 22 characters
  and the buffer grew without bound.
* #8 a base64-wrapped key (``base64 id_rsa``) streamed as JSON text deltas kept
  every continuation delta verbatim in the done step's raw output.
* #9 a Codex usage total above 2**53 made the step unrecordable and ended the run.
* #10 ``NaN``/``Infinity`` in a CLI's JSON event made the step unrecordable and
  ended the run.
"""

from __future__ import annotations

import base64
import json
import random
import sys

import pytest

from opentine.harnesses import CodexCLIHarness, GenericHarness, OpentineHarness
from opentine.harnesses._codex_events import _count
from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines
from opentine.harnesses._types import MAX_COUNT, parse_json_event
from tests.test_harness_core_0_10 import _printer, _record, _stored_bytes
from tests.test_harness_key_deltas_0_10 import _gemini, _harness, _hermes, _split, _stream_lines

# A stand-in PEM: real-looking armor and body lines, no actual key material.
_PEM_BODY = [f"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ{n:014d}" for n in range(12)]
_PEM = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(_PEM_BODY) + "\n-----END PRIVATE KEY-----\n"
_B64 = base64.b64encode(_PEM.encode()).decode()
_WRAPPED = "\n".join(_B64[i : i + 76] for i in range(0, len(_B64), 76))


def _deltas_text() -> str:
    return "Here is the encoded key:\n" + _WRAPPED + "\nKeep it safe."


def _assert_no_recoverable_key(text: str) -> None:
    """Neither a body line nor a base64 stretch that decodes to one survives."""
    for line in _PEM_BODY:
        assert line not in text
    for line in _WRAPPED.splitlines()[1:]:  # the first line is the encoded marker
        assert line[8:40] not in text, line


def test_the_output_cap_charges_the_raw_marker_line_it_keeps(tmp_path):
    lines = []
    for _ in range(5):
        lines += ["-----BEGIN PRIVATE KEY----- " + "A" * 200_000, "x"]
    harness = GenericHarness(
        command=_printer(tmp_path, lines), cwd=tmp_path, max_output_chars=300_000
    )
    with pytest.raises(Exception, match="exceeds 300000 characters"):
        OpentineHarness(harness).run_sync("task")


@pytest.mark.parametrize("shape", [_gemini, _hermes])
@pytest.mark.parametrize("seed", range(4))
def test_a_base64_wrapped_key_streamed_as_deltas_is_masked(shape, seed):
    text = _deltas_text()
    rng = random.Random(seed)
    for _ in range(60):
        pieces = rng.randint(2, 40)
        cuts = rng.sample(range(1, len(text)), pieces - 1)
        keys = KeyLines()
        joined = []
        for delta in _split(text, cuts):
            masked = json.loads(keys.mask(json.dumps(shape(delta))))
            joined.append(masked.get("content", masked.get("text")))
        out = "".join(joined)
        _assert_no_recoverable_key(out)
        assert out.startswith("Here is the encoded key:\n")


@pytest.mark.parametrize("name", ["gemini", "hermes"])
def test_a_streamed_base64_key_never_reaches_the_saved_record(tmp_path, name):
    deltas = [_deltas_text()[i : i + 37] for i in range(0, len(_deltas_text()), 37)]
    run, recorded = _record(_harness(name, tmp_path, _stream_lines(name, deltas)))
    _assert_no_recoverable_key(recorded)
    _assert_no_recoverable_key(_stored_bytes(run, tmp_path).decode("utf-8", "replace"))
    assert PLACEHOLDER in recorded


def test_prose_deltas_after_the_wrapped_key_are_kept():
    keys = KeyLines()
    out = []
    for delta in [*_split(_deltas_text(), [30, 400]), " Rotate it now."]:
        out.append(json.loads(keys.mask(json.dumps(_gemini(delta))))["content"])
    assert "".join(out).endswith("Keep it safe. Rotate it now.")


@pytest.mark.parametrize("value", [2**53, 2**60, 10**400, -1, 1.5, True, None, "9"])
def test_codex_counts_past_the_safe_bound_are_ignored(value):
    assert _count(value) == 0
    assert _count(MAX_COUNT) == MAX_COUNT


def test_a_huge_codex_usage_total_does_not_end_the_run(tmp_path):
    events = [
        {"type": "thread.started", "thread_id": "t"},
        {"type": "item.completed", "item": {"id": "a", "type": "agent_message", "text": "before"}},
        {"type": "turn.completed", "usage": {"input_tokens": 2**60, "output_tokens": 3}},
        {"type": "item.completed", "item": {"id": "b", "type": "agent_message", "text": "after"}},
        {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 5}},
    ]
    script = _printer(tmp_path, [json.dumps(e) for e in events])
    run = OpentineHarness(CodexCLIHarness(command=script, cwd=tmp_path)).run_sync("task")
    assert run.status.value == "completed"
    assert "after" in "\n".join(str(step.inputs) + str(step.outputs) for step in run.steps)


def test_nan_and_infinity_in_an_event_read_as_null():
    event = parse_json_event(
        '{"type":"tool_use","parameters":{"n":NaN,"m":Infinity,"k":-Infinity}}'
    )
    assert event == {"type": "tool_use", "parameters": {"n": None, "m": None, "k": None}}


@pytest.mark.parametrize("name", ["gemini", "hermes"])
def test_nan_in_a_cli_event_does_not_end_the_run(tmp_path, name):
    lines = _stream_lines(name, ["hello"])
    tool = (
        '{"type":"tool_use","tool_name":"calc","tool_id":"t","parameters":{"n":NaN}}'
        if name == "gemini"
        else '{"type":"tool_call","name":"calc","arguments":{"n":NaN,"x":Infinity}}'
    )
    lines.insert(1, tool)
    run, _ = _record(_harness(name, tmp_path, lines))
    assert run.status.value == "completed"
    run.save(tmp_path / "saved.tine")  # the record stays canonical JSON


def test_every_dialect_survives_non_finite_constants(tmp_path):
    from opentine.harnesses import HARNESS_CLASSES

    rng = random.Random(6)
    for name, cls in sorted(HARNESS_CLASSES.items()):
        harness = cls(command=(sys.executable, "-c", "pass"), cwd=tmp_path)
        for _ in range(40):
            token = rng.choice(["NaN", "Infinity", "-Infinity"])
            field = rng.choice(["cost", "duration", "usage", "input", "parameters", "text"])
            kind = rng.choice(["result", "message", "tool_use", "x"])
            harness.parse_line(f'{{"type":"{kind}","{field}":{token}}}')
