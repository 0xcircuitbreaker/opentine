"""Final security pass 2 (0.10.0) harness fixes, pinned.

* #7 a private key printed base64-wrapped (``base64 id_rsa``) on text stdout or
  on stderr reached the record line by line, because each raw line is its own
  step and the record's scrubber needs the wrapped lines together.
* #8 trimming a long line inside an open key block was quadratic.
* #9 one malformed CLI event raised out of ``parse_line`` and ended the run.
"""

from __future__ import annotations

import base64
import copy
import json
import random
import time
from pathlib import Path

import pytest

from opentine._cli_common import HARNESS_FACTORIES
from opentine.harnesses import ClaudeCodeHarness, GenericHarness, OpentineHarness
from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines
from tests.test_harness_core_0_10 import KEY_BODY, _printer, _record, _stored_bytes

_ARMORS = [
    "RSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "EC PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
]


def _wrapped(armor: str, width: int) -> list[str]:
    pem = f"-----BEGIN {armor}-----\n" + "\n".join(KEY_BODY * 4) + f"\n-----END {armor}-----\n"
    encoded = base64.b64encode(pem.encode()).decode()
    if not width:
        return [encoded]
    return [encoded[i : i + width] for i in range(0, len(encoded), width)]


def _assert_absent(lines: list[str], recorded: str, stored: bytes) -> None:
    for line in lines:
        assert line not in recorded
        assert line.encode() not in stored


@pytest.mark.parametrize("armor", _ARMORS)
@pytest.mark.parametrize("width", [76, 64, 0])
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_a_base64_wrapped_key_never_reaches_the_record(tmp_path, armor, width, stream):
    lines = _wrapped(armor, width)
    printed = ["running: base64 ~/.ssh/id_rsa", *lines, "done."]
    if stream == "stdout":
        harness = GenericHarness(command=_printer(tmp_path, printed), cwd=tmp_path)
    else:
        harness = ClaudeCodeHarness(
            command=_printer(tmp_path, [], stderr=printed),
            extra_args=("--output-format", "stream-json"),
            cwd=tmp_path,
        )
    run, recorded = _record(harness)
    _assert_absent(lines, recorded, _stored_bytes(run, tmp_path))
    assert PLACEHOLDER in recorded and "done." in recorded


def test_base64_masking_closes_at_the_first_non_base64_line():
    keys = KeyLines()
    lines = _wrapped("RSA PRIVATE KEY", 76)
    masked = [keys.mask(line) for line in ["$ base64 k", *lines, "$ ls", "README.md"]]
    assert masked == ["$ base64 k", *[PLACEHOLDER] * len(lines), "$ ls", "README.md"]


def test_base64_that_is_not_a_private_key_is_left_alone():
    keys = KeyLines()
    cert = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n").decode()
    assert keys.mask(cert) == cert and not keys.wrapped
    assert keys.mask("QUJDREVGR0g=") == "QUJDREVGR0g="


def _open_block_line_time(size: int) -> float:
    keys = KeyLines()
    keys.mask("-----BEGIN PRIVATE KEY-----")
    line = "AAAA" + "\\n" * size
    start = time.perf_counter()
    keys.mask(line)
    return time.perf_counter() - start


def test_a_long_line_inside_an_open_key_block_is_linear():
    small, large = _open_block_line_time(50_000), _open_block_line_time(200_000)
    assert large < max(small, 0.005) * 12
    assert _open_block_line_time(500_000) < 2.0  # a ~1 MB line


# --------------------------------------------------------------------------- #
# #9: parse_line never raises
# --------------------------------------------------------------------------- #

_VALUES = [None, 0, -1, 2.5, "x", "", [], {}, [1, "a"], {"a": 1}, True, "NaN", "-3", ["x"]]
_KEYS = [
    "type", "kind", "event", "role", "model", "usage", "tool_calls", "cost", "price",
    "duration", "message", "content", "text", "delta", "part", "item", "result",
    "total_cost_usd", "stats", "id", "name", "arguments", "subtype", "error", "properties",
]  # fmt: skip
_FIXTURES = Path(__file__).parent / "fixtures" / "harness"


def _fixture_events() -> list[dict]:
    events = []
    for path in sorted(_FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                events.append(value)
    return events


def _leaves(node, prefix=()):
    stack = [(node, prefix)]
    while stack:
        current, path = stack.pop()
        if path:
            yield path
        items = (
            current.items()
            if isinstance(current, dict)
            else (enumerate(current) if isinstance(current, list) else ())
        )
        stack.extend((value, (*path, key)) for key, value in items)


def _mutated(event: dict, rng: random.Random) -> dict:
    event = copy.deepcopy(event)
    for _ in range(rng.randint(1, 3)):
        paths = list(_leaves(event))  # recomputed: an earlier change may remove a path
        if not paths:
            break
        path = rng.choice(paths)
        node = event
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = copy.deepcopy(rng.choice(_VALUES))
    return event


def _random_event(rng: random.Random) -> dict:
    return {key: copy.deepcopy(rng.choice(_VALUES)) for key in rng.sample(_KEYS, 4)}


@pytest.mark.parametrize("name", sorted(HARNESS_FACTORIES))
def test_parse_line_never_raises_on_a_malformed_event(name):
    harness = HARNESS_FACTORIES[name]()
    events = _fixture_events()
    rng = random.Random(name)
    for index in range(1000):
        event = _mutated(rng.choice(events), rng) if index % 2 else _random_event(rng)
        harness.parse_line(json.dumps(event))


@pytest.mark.parametrize(
    ("name", "line"),
    [
        ("cursor", '{"type":["x"]}'),
        ("codex", '{"type":{"a":1}}'),
        ("kimi-code", '{"role":"assistant","tool_calls":5}'),
    ],
)
def test_the_reported_crash_shapes_parse(name, line):
    HARNESS_FACTORIES[name]().parse_line(line)


@pytest.mark.parametrize("cost", ["n/a", -5, True, 1e309])
def test_a_malformed_cost_is_ignored_with_a_warning(cost):
    step = GenericHarness().parse_line(json.dumps({"type": "message", "cost": cost}))
    assert step.cost == 0.0
    # ``Infinity`` now reads as null (final pass 6, #10): no figure, no warning.
    if cost != 1e309:
        assert step.inputs["meter_warning"] == "malformed cost ignored"


def test_a_malformed_event_does_not_end_the_run_or_lose_its_cost(tmp_path):
    result = {"type": "result", "subtype": "success", "total_cost_usd": 0.5, "modelUsage": {}}
    lines = ['{"type":"stats","cost":"n/a"}', '{"type":["x"]}', json.dumps(result)]
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run = OpentineHarness(harness).run_sync("task")
    assert run.status.value == "completed"
    assert run.total_cost == pytest.approx(0.5)
