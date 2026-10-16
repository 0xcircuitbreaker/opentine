"""Final security pass 5 (0.10.0) harness fixes, pinned.

* #9 a private key printed with a per-line decoration -- a ``#``/``//``/``;``
  comment leader, terminal colour codes, a table border -- closed the masking
  block on its first body line, so the body reached every step and, with its
  ``BEGIN`` marker already cut, the joined done-step output that 0.9.2's
  scrubber still redacted.
* #10 a JSON integer too large for a float in a CLI event's cost or duration
  raised ``OverflowError`` out of the reader and ended the run.
"""

from __future__ import annotations

import json
import random

import pytest

from opentine._cli_common import HARNESS_FACTORIES
from opentine.harnesses import ClaudeCodeHarness, GenericHarness, OpentineHarness
from opentine.harnesses._dialect_base import count, money
from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines, buffered
from opentine.harnesses._types import duration_seconds, reported_meter
from opentine.redaction import redact_text
from tests.test_harness_core_0_10 import KEY_BODY, _printer, _record, _stored_bytes

_ARMORS = [
    "RSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
]
#: (prefix, suffix) a tool or file puts around each line it prints.
_DECOR = [
    ("# ", ""),
    ("#", ""),
    ("// ", ""),
    ("; ", ""),
    ("-- ", ""),
    ("% ", ""),
    (" * ", ""),
    ("\x1b[32m", "\x1b[0m"),
    ("\x1b[1;31m", "\x1b[m"),
    ("│ ", " │"),
    ("| ", " |"),
    ("#\x1b[33m ", "\x1b[0m"),
    ("  12  # ", ""),
    ("config.py:7:# ", ""),
]


def _key(armor: str, prefix: str, suffix: str) -> list[str]:
    lines = [f"-----BEGIN {armor}-----", *KEY_BODY, f"-----END {armor}-----"]
    return [prefix + line + suffix for line in lines]


@pytest.mark.parametrize("armor", _ARMORS)
@pytest.mark.parametrize(("prefix", "suffix"), _DECOR)
def test_a_decorated_key_body_is_masked_line_by_line(armor, prefix, suffix):
    keys = KeyLines()
    masked = [keys.mask(line) for line in [*_key(armor, prefix, suffix), "after"]]
    assert not any(body in line for body in KEY_BODY for line in masked)
    assert masked[-1] == "after" and not keys.open


@pytest.mark.parametrize("armor", _ARMORS)
@pytest.mark.parametrize(("prefix", "suffix"), _DECOR)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_a_decorated_key_never_reaches_the_saved_record(tmp_path, armor, prefix, suffix, stream):
    printed = ["$ cat config", *_key(armor, prefix, suffix), "done."]
    if stream == "stdout":
        harness = GenericHarness(command=_printer(tmp_path, printed), cwd=tmp_path)
    else:
        harness = ClaudeCodeHarness(
            command=_printer(tmp_path, [], stderr=printed),
            extra_args=("--output-format", "stream-json"),
            cwd=tmp_path,
        )
    run, recorded = _record(harness)
    assert not any(body in recorded for body in KEY_BODY)
    stored = _stored_bytes(run, tmp_path)
    assert not any(body.encode() in stored for body in KEY_BODY)
    assert b"done." in stored


@pytest.mark.parametrize(("prefix", "suffix"), _DECOR)
def test_the_joined_output_is_never_less_redacted_than_the_raw_text(prefix, suffix):
    # Whatever line-wise masking decides, the joined output the done step keeps
    # holds the block's markers, so the record scrubber removes everything
    # between them -- at least what it removes from the raw text.
    raw = ["$ cat config", *_key("RSA PRIVATE KEY", prefix, suffix), "done."]
    keys = KeyLines()
    joined = "\n".join(buffered(keys, line, keys.mask(line)) for line in raw)
    scrubbed, baseline = redact_text(joined), redact_text("\n".join(raw))
    assert not any(body in scrubbed for body in KEY_BODY)
    assert not any(body in baseline for body in KEY_BODY)
    assert scrubbed.endswith("done.")


def test_a_misjudged_body_line_is_still_redacted_in_the_done_output(tmp_path):
    # A body line no decoration rule recognises still sits between the raw
    # markers in the joined output, and the scrubber removes it on save.
    odd = "~~ " + KEY_BODY[0] + " ~~"
    printed = ["-----BEGIN RSA PRIVATE KEY-----", odd, "-----END RSA PRIVATE KEY-----", "done."]
    keys = KeyLines()
    joined = "\n".join(buffered(keys, line, keys.mask(line)) for line in printed)
    assert KEY_BODY[0] not in redact_text(joined)


def test_clean_lines_and_json_events_keep_their_masked_form():
    keys = KeyLines()
    assert buffered(keys, "plain", keys.mask("plain")) == "plain"
    event = json.dumps({"type": "text", "text": "-----BEGIN RSA PRIVATE KEY-----\n" + KEY_BODY[0]})
    masked = keys.mask(event)
    assert buffered(keys, event, masked) == masked and KEY_BODY[0] not in masked


def test_a_double_slash_is_only_a_comment_leader_before_whitespace():
    keys = KeyLines()
    body = "//" + KEY_BODY[0][2:]  # base64 may start with "/"
    lines = ["-----BEGIN RSA PRIVATE KEY-----", body, "-----END RSA PRIVATE KEY-----"]
    assert [keys.mask(line) for line in lines][1] == PLACEHOLDER


_HUGE = [10**400, -(10**400), 10**20, 1e308, "1" + "0" * 400, "NaN", "inf", "-1e999", 2**63]


@pytest.mark.parametrize("value", _HUGE)
def test_numeric_helpers_never_raise_on_huge_or_odd_numbers(value):
    assert money(value) == 0.0 or 0 <= money(value) <= 1e15
    assert 0 <= count(value) <= 2**53 - 1
    seconds = duration_seconds({"duration": value})
    assert 0 <= seconds <= 1e15
    cost, warning = reported_meter({"cost": value}, "cost")
    assert cost == 0.0 or 0 <= cost <= 1e15
    if cost == 0.0 and value not in (0,):
        assert warning == {"meter_warning": "malformed cost ignored"}


_NUMERIC_KEYS = (
    "cost", "price", "duration", "duration_ms", "total_cost_usd", "cost_usd",
    "input_tokens", "output_tokens", "tokens", "inputTokens", "outputTokens",
)  # fmt: skip


@pytest.mark.parametrize("name", sorted(HARNESS_FACTORIES))
def test_no_harness_parser_raises_on_huge_numbers(name):
    harness = HARNESS_FACTORIES[name]()
    rng = random.Random(name)
    shapes = [
        {"type": "result"},
        {"type": "result", "stats": {}},
        {"type": "message", "usage": {}},
        {"type": "step_finish", "part": {"tokens": {}}},
        {"type": "turn.completed", "usage": {}},
        {"type": "assistant", "message": {"usage": {}}},
    ]
    for _ in range(300):
        event = json.loads(json.dumps(rng.choice(shapes)))
        holder = next((v for v in event.values() if isinstance(v, dict)), event)
        for key in rng.sample(_NUMERIC_KEYS, 3):
            holder[key] = rng.choice(_HUGE)
            event[key] = rng.choice(_HUGE)
        harness.parse_line(json.dumps(event))


def test_a_huge_cost_does_not_end_the_run_or_lose_later_events(tmp_path):
    huge = "1" + "0" * 400
    lines = [
        '{"type":"system","subtype":"init","model":"claude-opus-5-5"}',
        '{"type":"result","subtype":"success","total_cost_usd":'
        + huge
        + ',"duration_ms":'
        + huge
        + ',"modelUsage":{}}',
        '{"type":"result","subtype":"success","total_cost_usd":0.5,"modelUsage":{}}',
    ]
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run = OpentineHarness(harness).run_sync("task")
    assert run.status.value == "completed"
    assert run.total_cost == pytest.approx(0.5)
