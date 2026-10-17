"""A private key a streaming CLI prints across several JSON delta events.

Final security pass 3, #5: masking each delta event alone replaced ``BEGIN``..end
of the first delta and returned the later deltas unchanged, so the joined think
step and the raw output kept the key body with no marker left for the record's
scrubber. The block now follows the delta's string path into later events, and a
marker split between two deltas is joined through a short carry.
"""

from __future__ import annotations

import json
import random
import sys

import pytest

from opentine.harnesses import HARNESS_CLASSES, ClaudeCodeHarness
from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines
from tests.test_harness_core_0_10 import KEY_BODY, _record, _stored_bytes

_ARMORS = (
    "RSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)


def _text(armor: str) -> str:
    block = [f"-----BEGIN {armor}-----", *KEY_BODY, f"-----END {armor}-----"]
    return "Here is the key:\n" + "\n".join(block) + "\nKeep it safe."


def _gemini(delta: str) -> dict:
    return {"type": "message", "role": "assistant", "content": delta, "delta": True}


def _hermes(delta: str) -> dict:
    return {"type": "text", "text": delta}


def _claude(delta: str) -> dict:
    return {
        "type": "stream_event",
        "event": {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": delta},
        },
    }


_SHAPES = {"gemini": _gemini, "hermes": _hermes, "claude": _claude}


def _texts(event: dict) -> str:
    if event["type"] == "message":
        return event["content"]
    if event["type"] == "text":
        return event["text"]
    return event["event"]["delta"]["text"]


def _split(text: str, cuts: list[int]) -> list[str]:
    edges = [0, *sorted(cuts), len(text)]
    return [text[a:b] for a, b in zip(edges, edges[1:])]


def _masked_join(shape, deltas: list[str]) -> str:
    keys = KeyLines()
    out = []
    for delta in deltas:
        masked = keys.mask(json.dumps(shape(delta)))
        out.append(_texts(json.loads(masked)))
    return "".join(out)


def _assert_no_body(text: str) -> None:
    for line in KEY_BODY:
        for start in range(0, len(line) - 11):
            assert line[start : start + 12] not in text, (line[start : start + 12], text)


@pytest.mark.parametrize("armor", _ARMORS)
@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_a_key_split_once_at_every_offset_never_survives(armor, shape):
    text = _text(armor)
    for cut in range(1, len(text)):
        joined = _masked_join(_SHAPES[shape], _split(text, [cut]))
        _assert_no_body(joined)
        assert PLACEHOLDER in joined or "BEGIN" in joined  # never body without a marker


@pytest.mark.parametrize("armor", _ARMORS)
@pytest.mark.parametrize("pieces", [3, 4, 5])
def test_a_key_split_across_several_deltas_never_survives(armor, pieces):
    text = _text(armor)
    rng = random.Random(f"{armor}-{pieces}")
    for _ in range(300):
        cuts = rng.sample(range(1, len(text)), pieces - 1)
        for shape in _SHAPES.values():
            _assert_no_body(_masked_join(shape, _split(text, cuts)))


def test_prose_after_a_closed_block_is_kept():
    deltas = _split(_text("RSA PRIVATE KEY"), [30, 120])
    joined = _masked_join(_gemini, [*deltas, " Next steps: rotate it."])
    assert joined.endswith(" Next steps: rotate it.")
    assert joined.startswith("Here is the key:\n")


def test_other_fields_of_a_delta_event_are_untouched():
    keys = KeyLines()
    first, second = _split(_text("RSA PRIVATE KEY"), [40])
    keys.mask(json.dumps(_gemini(first)))
    event = json.loads(keys.mask(json.dumps(_gemini(second))))
    assert (event["type"], event["role"], event["delta"]) == ("message", "assistant", True)


def _stream_lines(name: str, deltas: list[str]) -> list[str]:
    if name == "gemini":
        head = [{"type": "init", "session_id": "s", "model": "gemini-3.8-flash"}]
        body = [_gemini(d) for d in deltas]
        tail = [{"type": "result", "status": "success", "stats": {}}]
    elif name == "hermes":
        head = [{"type": "system", "subtype": "init", "model": "m", "session_id": "h"}]
        body = [_hermes(d) for d in deltas]
        tail = [{"type": "result", "session_id": "h", "exit_code": 0, "text": "done"}]
    else:
        head = [{"type": "system", "subtype": "init", "model": "claude-opus-5-5"}]
        body = [_claude(d) for d in deltas]
        tail = [{"type": "result", "subtype": "success", "result": "done", "usage": {}}]
    return [json.dumps(event) for event in (*head, *body, *tail)]


def _harness(name: str, tmp_path, lines: list[str]):
    (tmp_path / "out.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    script = "import sys; sys.stdout.write(open('out.txt').read())"
    if name == "claude-code":
        tail = ("--output-format", "stream-json", "--include-partial-messages")
        return ClaudeCodeHarness(
            command=(sys.executable, "-c", script), extra_args=tail, cwd=tmp_path
        )
    cls = HARNESS_CLASSES[name]
    return cls(command=(sys.executable, "-c", script, *cls.default_command[1:]), cwd=tmp_path)


@pytest.mark.parametrize("name", ["gemini", "hermes", "qwen-code", "claude-code"])
@pytest.mark.parametrize("cuts", [[25], [21, 60, 140], [5, 23, 200, 260]])
def test_a_streamed_key_never_reaches_the_saved_record(tmp_path, name, cuts):
    shape = {"gemini": "gemini", "hermes": "hermes"}.get(name, "claude")
    deltas = _split(_text("OPENSSH PRIVATE KEY"), cuts)
    run, recorded = _record(_harness(name, tmp_path, _stream_lines(shape, deltas)))
    stored = _stored_bytes(run, tmp_path).decode("utf-8", "replace")
    _assert_no_body(recorded)
    _assert_no_body(stored)
